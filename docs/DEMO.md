# Demo and Acceptance Walkthrough

This document captures a validated lab/demo walkthrough. It is not the normative production specification.

## Lab Environment

- Client: `192.168.131.128`
- CA / Broker: `192.168.131.135`
- soc / Server: `192.168.131.134`
- Broker UI: `http://192.168.131.135:8443/ui`

## Demo Tokens

Temporary demo tokens used during testing:

- `admin-token-123`
- `client-token-123`
- `server-token-123`

Replace them before broader rollout.

## Recommended Live Demo Sequence

1. Open `/ui` on the CA host.
2. Enter `admin-token-123` and click `Use Token`.
3. In step 1, run:
   - `/healthz`
   - `/v1/ui/bootstrap`
4. Explain the three-machine topology shown at the top.
5. In step 2, fetch:
   - user CA pubkey
   - host CA pubkey
6. In step 3:
   - click `Auto Fill Demo Public Key`
   - click `Sign User Cert`
   - click `Inspect Returned Cert`
7. In step 4:
   - click `Auto Fill Demo Host Public Key`
   - click `Sign Host Cert`
   - click `Inspect Returned Cert`
8. Show the runtime state panel updating as each asset appears.

## Real Validation Completed

The environment has already been exercised end-to-end:

- user cert issuance succeeded
- host cert issuance succeeded
- soc loaded host certificate and trusted user CA
- `root@192.168.131.134` login with user certificate succeeded
- `rocky@192.168.131.134` login with user certificate succeeded after creating the local `rocky` account

## Expected Files by Role

Client:

- `~/.ssh/id_ed25519`
- `~/.ssh/id_ed25519.pub`
- `~/.ssh/id_ed25519-cert.pub`
- `known_hosts` entry with `@cert-authority ... <host_ca_pub>`

soc / Server:

- `/etc/ssh/ssh_host_ed25519_key`
- `/etc/ssh/ssh_host_ed25519_key.pub`
- `/etc/ssh/ssh_host_ed25519_key-cert.pub`
- trusted user CA pubkey file referenced by `TrustedUserCAKeys`

CA / Broker:

- `/root/.step/secrets/ssh_user_ca_key`
- `/root/.step/secrets/ssh_host_ca_key`
- `/root/.step/certs/ssh_user_ca_key.pub`
- `/root/.step/certs/ssh_host_ca_key.pub`

## Troubleshooting

## Bootstrap Notes

- `BROKER_URL` should be explicitly set for both bootstrap scripts. Outside localhost, use `https://...`.
- `HOST_PATTERN` is required for the client bootstrap script so the host CA trust scope is explicit.
- The server bootstrap script now injects `AuthenticationMethods publickey`, `ExposeAuthInfo yes`, and `RevokedKeys /etc/ssh/revoked_keys` when missing.

- `INTERNAL_ERROR` on CA pubkey fetch usually means the broker cannot read the configured CA public key path.
- `SIGNING_FAILED` with passphrase text means the SSH CA key passphrase is missing or wrong.
- `Permission denied` on SSH login usually means:
  - target local account does not exist, or
  - `TrustedUserCAKeys` points at the wrong CA pubkey path, or
  - host CA was not trusted on the client side.
