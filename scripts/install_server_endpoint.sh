#!/usr/bin/env bash
set -euo pipefail

BROKER_URL="${BROKER_URL:-https://broker.example.internal}"
SERVER_TOKEN="${SERVER_TOKEN:?SERVER_TOKEN is required}"
HOST_KEY_PATH="${HOST_KEY_PATH:-/etc/ssh/ssh_host_ed25519_key}"
HOST_CERT_PATH="${HOST_CERT_PATH:-/etc/ssh/ssh_host_ed25519_key-cert.pub}"
TRUSTED_USER_CA_PATH="${TRUSTED_USER_CA_PATH:-/etc/ssh/trusted_user_ca_keys.pub}"
HOST_PRINCIPAL="${HOST_PRINCIPAL:-$(hostname -f 2>/dev/null || hostname)}"
KEY_ID="${KEY_ID:-host-bootstrap:${HOST_PRINCIPAL}}"
TTL="${TTL:-1095d}"
CALLER_NAME="${CALLER_NAME:-server-bootstrap}"
CALLER_SOURCE_IP="${CALLER_SOURCE_IP:-}"
export HOST_PRINCIPAL KEY_ID TTL CALLER_NAME CALLER_SOURCE_IP

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
  python3 - <<'PY'
import ipaddress
import os
import re
import sys

value = os.environ["HOST_PRINCIPAL"]
hostname_pattern = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)
try:
    ipaddress.ip_address(value)
except ValueError:
    if not hostname_pattern.fullmatch(value):
        sys.stderr.write(f"ERROR: HOST_PRINCIPAL is not a valid IP or hostname: {value}\n")
        raise SystemExit(1)
PY
}

validate_broker_url
validate_inputs

CURL_COMMON_ARGS=(-fsS --connect-timeout 5 --max-time 30)
CURL_COMMON_ARGS+=("${CURL_SECURITY_ARGS[@]}")

mkdir -p /etc/ssh
chmod 755 /etc/ssh

if [[ ! -f "${HOST_KEY_PATH}" ]]; then
  ssh-keygen -t ed25519 -N "" -f "${HOST_KEY_PATH}"
fi

HOST_PUBLIC_KEY="$(cat "${HOST_KEY_PATH}.pub")"
export HOST_PUBLIC_KEY

curl "${CURL_COMMON_ARGS[@]}" \
  -H "Authorization: Bearer ${SERVER_TOKEN}" \
  "${BROKER_URL}/v1/ca/user/pubkey" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])' \
  > "${TRUSTED_USER_CA_PATH}"
chmod 644 "${TRUSTED_USER_CA_PATH}"

curl "${CURL_COMMON_ARGS[@]}" \
  -H "Authorization: Bearer ${SERVER_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST "${BROKER_URL}/v1/sign/host" \
  -d "$(python3 - <<'PY'
import json
import os
payload = {
    "public_key": os.environ["HOST_PUBLIC_KEY"],
    "key_id": os.environ["KEY_ID"],
    "requested_principals": [os.environ["HOST_PRINCIPAL"]],
    "ttl": os.environ["TTL"],
    "caller": {
        "requester": os.environ["CALLER_NAME"],
      "source_ip": os.environ.get("CALLER_SOURCE_IP") or None,
        "reason": "host certificate bootstrap",
    },
}
print(json.dumps(payload))
PY
)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["certificate"])' \
  > "${HOST_CERT_PATH}"
chmod 644 "${HOST_CERT_PATH}"

grep -q '^TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys.pub$' /etc/ssh/sshd_config || \
  printf '\nTrustedUserCAKeys /etc/ssh/trusted_user_ca_keys.pub\n' >> /etc/ssh/sshd_config
grep -q '^HostKey /etc/ssh/ssh_host_ed25519_key$' /etc/ssh/sshd_config || \
  printf 'HostKey /etc/ssh/ssh_host_ed25519_key\n' >> /etc/ssh/sshd_config
grep -q '^HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub$' /etc/ssh/sshd_config || \
  printf 'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\n' >> /etc/ssh/sshd_config
grep -q '^AuthenticationMethods publickey$' /etc/ssh/sshd_config || \
  printf 'AuthenticationMethods publickey\n' >> /etc/ssh/sshd_config
grep -q '^ExposeAuthInfo yes$' /etc/ssh/sshd_config || \
  printf 'ExposeAuthInfo yes\n' >> /etc/ssh/sshd_config
grep -q '^RevokedKeys /etc/ssh/revoked_keys$' /etc/ssh/sshd_config || \
  printf 'RevokedKeys /etc/ssh/revoked_keys\n' >> /etc/ssh/sshd_config

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload sshd || systemctl restart sshd
else
  service sshd reload || service ssh reload
fi

ssh-keygen -Lf "${HOST_CERT_PATH}" || true
