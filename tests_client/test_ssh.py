from zfcssh_client.paths import default_paths
from zfcssh_client.ssh import build_ssh_command


def test_build_ssh_command_includes_certificate_and_known_hosts(tmp_path) -> None:
    paths = default_paths(tmp_path / "home")
    command = build_ssh_command(target="root@soc.example.internal", paths=paths, remote_command=["uname", "-a"])

    assert command[0] == "ssh"
    assert str(paths.user_key_path) in command
    assert f"CertificateFile={paths.user_cert_path}" in command
    assert f"UserKnownHostsFile={paths.known_hosts_path}" in command
    assert command[-2:] == ["uname", "-a"]
