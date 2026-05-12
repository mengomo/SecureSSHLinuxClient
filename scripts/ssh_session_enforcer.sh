#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# ssh_session_enforcer.sh
#
# Periodically scans active SSH sessions and terminates any whose certificate
# has expired.  Run via the companion systemd timer every 60 seconds.
#
# Requires:  ExposeAuthInfo yes   in sshd_config
#            (gives each session a temp file containing the auth certificate)
#
# How it works:
#   1. Find all sshd child processes (one per authenticated session).
#   2. For each, locate the SSH_AUTH_INFO_FILE from /proc/<pid>/environ.
#   3. Extract the certificate from that file.
#   4. Parse the "Valid:" line with ssh-keygen -Lf to get the expiry time.
#   5. If now > expiry, send SIGHUP then SIGTERM to the session process tree.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

LOG_TAG="ssh-session-enforcer"
SSHD_CONFIG_PATH="${SSHD_CONFIG_PATH:-/etc/ssh/sshd_config}"

log() { logger -t "$LOG_TAG" "$*"; }

require_prerequisites() {
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        log "ERROR: ssh-keygen is not installed or not in PATH"
        exit 1
    fi

    if [[ ! -r "$SSHD_CONFIG_PATH" ]]; then
        log "ERROR: sshd_config is not readable: $SSHD_CONFIG_PATH"
        exit 1
    fi

    if ! grep -Eq '^[[:space:]]*ExposeAuthInfo[[:space:]]+yes([[:space:]]|$)' "$SSHD_CONFIG_PATH"; then
        log "ERROR: ExposeAuthInfo yes is required in $SSHD_CONFIG_PATH"
        exit 1
    fi
}

# ── locate sshd child processes (one per logged-in session) ──────────────────
find_session_pids() {
    # sshd forks:  main → per-connection → privsep-child + session-child
    # The session-child is the one with SSH_AUTH_INFO_FILE in its environment.
    # We look for sshd processes whose parent is also sshd.
    pgrep -a sshd | awk '{print $1}' | while read -r pid; do
        # skip if we cannot read the environ (e.g. main sshd or permission)
        env_file="/proc/${pid}/environ"
        [[ -r "$env_file" ]] || continue
        # only care about processes that have SSH_AUTH_INFO_FILE set
        if tr '\0' '\n' < "$env_file" 2>/dev/null | grep -q '^SSH_AUTH_INFO_FILE='; then
            echo "$pid"
        fi
    done
}

# ── extract certificate from auth info file ──────────────────────────────────
get_cert_from_auth_info() {
    local pid="$1"
    local env_file="/proc/${pid}/environ"
    [[ -r "$env_file" ]] || return 1

    local auth_info_path
    auth_info_path=$(tr '\0' '\n' < "$env_file" 2>/dev/null \
        | grep '^SSH_AUTH_INFO_FILE=' \
        | head -1 \
        | cut -d= -f2-)

    [[ -n "$auth_info_path" && -f "$auth_info_path" ]] || return 1

    # The auth info file may contain multiple lines.
    # For certificate auth, one line will be the certificate (starts with ssh-*-cert).
    local cert_line
    cert_line=$(grep -E '^ssh-[a-z0-9]+-cert-' "$auth_info_path" 2>/dev/null | head -1) || true

    if [[ -z "$cert_line" ]]; then
        # authenticated with plain key, not certificate – skip
        return 1
    fi

    echo "$cert_line"
}

# ── parse certificate expiry ─────────────────────────────────────────────────
get_cert_expiry_epoch() {
    local cert_line="$1"
    local tmp_cert
    tmp_cert=$(mktemp /tmp/enforcer-cert-XXXXXX.pub)
    echo "$cert_line" > "$tmp_cert"

    local valid_before
    valid_before=$(ssh-keygen -Lf "$tmp_cert" 2>/dev/null \
        | grep '^ *Valid:' \
        | sed 's/.*to //')

    rm -f "$tmp_cert"

    [[ -n "$valid_before" ]] || return 1

    # "forever" means no expiry
    if [[ "$valid_before" == "forever" ]]; then
        echo "0"
        return 0
    fi

    # Convert to epoch.  Format: 2026-03-23T19:00:00
    date -d "$valid_before" +%s 2>/dev/null || return 1
}

# ── get session info for logging ─────────────────────────────────────────────
get_session_user() {
    local pid="$1"
    # read UID from /proc/pid/status, then map to username
    local uid
    uid=$(awk '/^Uid:/{print $2}' "/proc/${pid}/status" 2>/dev/null) || return 1
    getent passwd "$uid" 2>/dev/null | cut -d: -f1
}

get_cert_key_id() {
    local cert_line="$1"
    local tmp_cert
    tmp_cert=$(mktemp /tmp/enforcer-cert-XXXXXX.pub)
    echo "$cert_line" > "$tmp_cert"

    local key_id
    key_id=$(ssh-keygen -Lf "$tmp_cert" 2>/dev/null \
        | grep '^ *Key ID:' \
        | sed 's/.*Key ID: "//;s/"//')

    rm -f "$tmp_cert"
    echo "${key_id:-unknown}"
}

# ── main loop ────────────────────────────────────────────────────────────────
main() {
    require_prerequisites

    local now
    now=$(date +%s)
    local killed=0

    for pid in $(find_session_pids); do
        local cert_line
        cert_line=$(get_cert_from_auth_info "$pid") || continue

        local expiry_epoch
        expiry_epoch=$(get_cert_expiry_epoch "$cert_line") || continue

        # 0 = no expiry (forever)
        [[ "$expiry_epoch" -eq 0 ]] && continue

        if (( now >= expiry_epoch )); then
            local user key_id
            user=$(get_session_user "$pid" || echo "?")
            key_id=$(get_cert_key_id "$cert_line")

            log "EXPIRED pid=$pid user=$user key_id=$key_id expired_at=$(date -d @"$expiry_epoch" --iso-8601=seconds) — terminating"

            # graceful: SIGHUP first, then SIGTERM after 5s
            kill -HUP "$pid" 2>/dev/null || true
            sleep 5
            kill -TERM "$pid" 2>/dev/null || true

            killed=$((killed + 1))
        fi
    done

    if (( killed > 0 )); then
        log "run complete: terminated $killed expired session(s)"
    fi
}

main "$@"
