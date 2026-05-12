import json

from zfcssh_client.bundle import import_bundle, load_installed_bundle
from zfcssh_client.paths import default_paths


def test_import_bundle_writes_metadata_and_pems(tmp_path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(
        json.dumps(
            {
                "bundle_id": "alice-laptop",
                "broker_url": "https://broker.example.internal",
                "mtls": {
                    "client_certificate_pem": "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
                    "client_key_pem": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
                    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
                },
                "ssh": {
                    "host_patterns": ["soc.example.internal"],
                    "default_principals": ["root"],
                    "default_profile": "field_operation",
                    "allowed_profiles": ["field_operation", "claims_warranty"],
                },
                "identity": {
                    "requester": "alice",
                    "reason": "field diagnostics",
                },
            }
        ),
        encoding="utf-8",
    )
    paths = default_paths(home)

    imported = import_bundle(bundle_path, paths)
    loaded = load_installed_bundle(paths)

    assert imported.bundle_id == "alice-laptop"
    assert loaded.broker_url == "https://broker.example.internal"
    assert paths.client_certificate_path.read_text(encoding="utf-8").startswith("-----BEGIN CERTIFICATE-----")
    assert loaded.allowed_profiles == ["field_operation", "claims_warranty"]
