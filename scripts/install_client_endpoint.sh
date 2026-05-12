#!/usr/bin/env bash
set -euo pipefail

BROKER_URL="${BROKER_URL:-https://broker.example.internal}"
CLIENT_TOKEN="${CLIENT_TOKEN:?CLIENT_TOKEN is required}"
USER_KEY_PATH="${USER_KEY_PATH:-$HOME/.ssh/id_ed25519}"
USER_CERT_PATH="${USER_CERT_PATH:-$HOME/.ssh/id_ed25519-cert.pub}"
KNOWN_HOSTS_PATH="${KNOWN_HOSTS_PATH:-$HOME/.ssh/known_hosts}"
HOST_PATTERN="${HOST_PATTERN:?HOST_PATTERN is required}"
USER_PRINCIPALS="${USER_PRINCIPALS:-rocky,root}"
KEY_ID="${KEY_ID:-$(id -un)@$(hostname -f 2>/dev/null || hostname)}"
TTL="${TTL:-24h}"
CALLER_NAME="${CALLER_NAME:-client-bootstrap}"
CALLER_SOURCE_IP="${CALLER_SOURCE_IP:-}"
export USER_PRINCIPALS KEY_ID TTL CALLER_NAME CALLER_SOURCE_IP

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

validate_broker_url() {
  case "${BROKER_URL}" in
    https://*)
      CURL_SECURITY_ARGS=(--proto '=https' --tlsv1.2)
      ;;
    http://localhost:*|http://127.0.0.1:*|http://[::1]:*)
      CURL_SECURITY_ARGS=()
      ;;
    *)
      fail "BROKER_URL must use https outside localhost: ${BROKER_URL}"
      ;;
  esac

  if [[ "${BROKER_URL}" == "https://broker.example.internal" ]]; then
    fail "BROKER_URL must be replaced with the real broker endpoint"
  fi
}

validate_inputs() {
  [[ "${KEY_ID}" =~ ^[A-Za-z0-9._:@/-]+$ ]] || \
    fail "KEY_ID contains unsupported characters: ${KEY_ID}"
  [[ "${USER_PRINCIPALS}" =~ ^[A-Za-z0-9._:@/-]+(,[A-Za-z0-9._:@/-]+)*$ ]] || \
    fail "USER_PRINCIPALS must be a comma-separated principal list"
  [[ "${HOST_PATTERN}" != "*" ]] || \
    fail "HOST_PATTERN must not trust every host when installing the host CA"
}

validate_broker_url
validate_inputs

CURL_COMMON_ARGS=(-fsS --connect-timeout 5 --max-time 30)
CURL_COMMON_ARGS+=("${CURL_SECURITY_ARGS[@]}")

mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

if [[ ! -f "${USER_KEY_PATH}" ]]; then
  ssh-keygen -t ed25519 -N "" -f "${USER_KEY_PATH}"
fi

USER_PUBLIC_KEY="$(cat "${USER_KEY_PATH}.pub")"
export USER_PUBLIC_KEY
HOST_CA_KEY="$(curl "${CURL_COMMON_ARGS[@]}" -H "Authorization: Bearer ${CLIENT_TOKEN}" "${BROKER_URL}/v1/ca/host/pubkey" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')"

if ! grep -q "@cert-authority ${HOST_PATTERN}" "${KNOWN_HOSTS_PATH}" 2>/dev/null; then
  printf '@cert-authority %s %s\n' "${HOST_PATTERN}" "${HOST_CA_KEY}" >> "${KNOWN_HOSTS_PATH}"
fi
chmod 600 "${KNOWN_HOSTS_PATH}"

curl "${CURL_COMMON_ARGS[@]}" \
  -H "Authorization: Bearer ${CLIENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST "${BROKER_URL}/v1/sign/user" \
  -d "$(python3 - <<'PY'
import json
import os
payload = {
    "public_key": os.environ["USER_PUBLIC_KEY"],
    "key_id": os.environ["KEY_ID"],
    "requested_principals": [item for item in os.environ["USER_PRINCIPALS"].split(",") if item],
    "ttl": os.environ["TTL"],
    "caller": {
        "requester": os.environ["CALLER_NAME"],
        "source_ip": os.environ.get("CALLER_SOURCE_IP") or None,
        "reason": "user certificate bootstrap",
    },
}
print(json.dumps(payload))
PY
)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["certificate"])' \
  > "${USER_CERT_PATH}"
chmod 600 "${USER_CERT_PATH}"

ssh-keygen -Lf "${USER_CERT_PATH}" || true
