# ZFCS Secure SSH Client

`zfcssh-client` is a Linux PC endpoint agent for SecureSSH workflows. It is responsible for:

- importing a Login Bundle that contains broker access metadata and mTLS material
- generating and storing the local SSH user private key
- authenticating to the cloud broker with mTLS
- requesting, validating, and installing SSH user certificates
- installing host CA trust for certificate-based host verification
- launching certificate-based SSH sessions to the board / SoC
- renewing short-lived user certificates before they expire

This repository now treats the Linux PC client as the primary deliverable. Cloud-side broker code may still exist in the tree for reference, but it is not the default package, entrypoint, or test target.

## Client Scope

Implemented in this project:

- Login Bundle import and local normalization
- mTLS HTTPS client for broker interactions
- SSH user key generation and certificate installation
- host CA trust installation through managed `known_hosts` entries
- certificate inspection and renewal-window checks using `ssh-keygen -Lf`
- `zfcssh` CLI for enrollment, verification, renewal, status, and SSH login
- `systemd --user` renewal timer units

Out of scope for this project:

- broker-side signing and policy enforcement
- server / SoC `sshd` hardening
- KRL generation and distribution
- Login Bundle issuance workflow

## Repository Layout

- `src/zfcssh_client/`: Linux PC client package
- `tests_client/`: unit tests for bundle import, cert parsing, and SSH command construction
- `systemd/user/`: user-scoped renewal service and timer
- `docs/login_bundle.example.json`: example bundle format consumed by the client

## Bundle Format

The client expects a JSON Login Bundle. The example file in `docs/login_bundle.example.json` shows the supported structure.

Required fields:

- `bundle_id`
- `broker_url`
- `mtls.client_certificate_pem` or `mtls.client_certificate_path`
- `mtls.client_key_pem` or `mtls.client_key_path`
- `ssh.host_patterns`
- `ssh.default_principals`
- `ssh.default_profile`

Optional fields:

- `mtls.ca_certificate_pem` or `mtls.ca_certificate_path`
- `ssh.allowed_profiles`
- `ssh.key_id`
- `identity.requester`
- `identity.reason`

## CLI

Install locally:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[test]
```

Import a bundle:

```bash
zfcssh bundle import docs/login_bundle.example.json
```

Enroll and install assets:

```bash
zfcssh enroll
```

Check local state:

```bash
zfcssh status
zfcssh verify
```

Renew only when needed:

```bash
zfcssh renew --if-needed
```

Open an SSH session to the board:

```bash
zfcssh ssh root@soc.example.internal
```

Run a remote command:

```bash
zfcssh ssh root@soc.example.internal -- uname -a
```

## Local Files

The client stores state in these default locations:

- `~/.config/zfcssh/bundle.json`
- `~/.config/zfcssh/mtls/client.crt`
- `~/.config/zfcssh/mtls/client.key`
- `~/.config/zfcssh/mtls/ca.crt`
- `~/.ssh/zfcssh_id_ed25519`
- `~/.ssh/zfcssh_id_ed25519-cert.pub`
- `~/.ssh/zfcssh_host_ca.pub`
- managed `@cert-authority` block in `~/.ssh/known_hosts`
- `~/.local/state/zfcssh/client.log`

## Renewal Timer

Install the user timer:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/user/zfcssh-renew.service ~/.config/systemd/user/
cp systemd/user/zfcssh-renew.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now zfcssh-renew.timer
```

## Validation

```bash
pytest
```
