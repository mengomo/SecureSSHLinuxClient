from datetime import datetime, timezone

from zfcssh_client.certificates import needs_renewal, parse_inspection_output


def test_parse_inspection_output_extracts_validity_and_principals() -> None:
    output = """
/tmp/id-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:test
        Signing CA: ED25519 SHA256:test
        Key ID: \"alice@laptop\"
        Serial: 12345
        Valid: from 2026-03-16T22:28:00 to 2026-03-17T22:28:00
        Principals:
                root
                lc:field_operation
        Critical Options: (none)
        Extensions:
                permit-pty
    """

    info = parse_inspection_output(output)

    assert info.valid_after == "2026-03-16T22:28:00"
    assert info.valid_before == "2026-03-17T22:28:00"
    assert info.principals == ["root", "lc:field_operation"]


def test_needs_renewal_when_inside_window() -> None:
    info = parse_inspection_output(
        """
/tmp/id-cert.pub:
        Valid: from 2026-03-16T00:00:00 to 2026-03-16T04:00:00
        Principals:
                root
        Critical Options: (none)
        Extensions:
                permit-pty
        """
    )

    assert needs_renewal(info, now=datetime(2026, 3, 16, 3, 5, tzinfo=timezone.utc)) is True
    assert needs_renewal(info, now=datetime(2026, 3, 16, 1, 0, tzinfo=timezone.utc)) is False
