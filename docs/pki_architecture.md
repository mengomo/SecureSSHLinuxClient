# PKI Architecture

## Design Position

This repository uses a layered trust model:

1. A commercial X.509 PKI governs trust above the SSH stack.
2. An SSH CA issues native OpenSSH user and host certificates.
3. `sshd` enforces principals, lifecycle stages, critical options, extensions, and revocation state.

The commercial X.509 PKI is not intended to replace the OpenSSH certificate format. It provides the higher-level trust, key-management, and transport-security boundary for the SSH CA based system.

## Why X.509 Does Not Replace the SSH CA

- `sshd` expects OpenSSH certificate blobs, not X.509 user certificates.
- Lifecycle access in this design depends on SSH principals such as `lc:field_operation`.
- SSH session controls such as `permit-port-forwarding` and `force-command` are native SSH certificate semantics.
- `AuthorizedPrincipalsCommand` and `RevokedKeys` operate on SSH-native trust anchors and serials.

Replacing the SSH CA with a direct X.509 leaf-certificate model would require a translation layer for principals, extensions, critical options, and revocation semantics. That adds protocol complexity without improving the sshd control plane.

## Recommended X.509 Landing Points

### 1. SSH CA Governance

Use the commercial X.509 PKI to protect, attest, or govern the SSH CA keys and their lifecycle. The SSH CA remains the issuer of OpenSSH certificates, while the X.509 PKI becomes the higher-level root of trust and operational control.

### 2. Broker Edge TLS

Use a TLS certificate issued by the commercial X.509 PKI on the broker edge, for example through nginx. This makes the network boundary explicit and aligns the broker URL with the formal trust model.

### 3. Optional mTLS

If a later phase requires stronger caller identity at the broker edge, add mTLS on top of the same X.509 PKI. This is an enhancement to the request path, not a replacement for SSH certificates.

## SSHD Security Layers

### Transport Layer

- HTTPS on the broker edge
- Restricted firewall exposure
- Optional mTLS for managed callers

### Host Identity Layer

- Host certificates signed by the SSH host CA
- Host CA public key distributed to clients

### User Authentication And Authorization Layer

- User certificates signed by the SSH user CA
- `TrustedUserCAKeys` on the server
- `AuthorizedPrincipalsCommand` for username and lifecycle-stage checks
- Lifecycle-stage allowlist on each server

### Session Lifetime Layer

- Certificate TTL enforced by `sshd`
- Active-session expiry enforced by the session enforcer timer
- Emergency revocation through KRL and `RevokedKeys`

### Audit And Operations Layer

- Broker audit logs for issuance events
- Server-side logs for principal validation and session expiry handling
- Operational runbooks for token rotation, KRL distribution, and incident handling

## Implementation Landing Points

- `app/config.py`: startup validation and trust-boundary configuration
- `app/services/signing.py`: SSH CA based signing path via `ssh-keygen -s`
- `nginx/zfcssh-broker.conf`: TLS edge configuration backed by the X.509 PKI
- `docs/sshd_config`: server baseline for `TrustedUserCAKeys`, `AuthorizedPrincipalsCommand`, `ExposeAuthInfo`, and `RevokedKeys`
- `scripts/authorized_principals_command.sh`: lifecycle-aware authorization
- `scripts/ssh_session_enforcer.sh`: active session expiry enforcement

## Release Implication

The formal release gate is not “does the broker answer HTTP requests”. It is “is the trust chain closed from X.509 governance down to SSH certificate enforcement on the server”.