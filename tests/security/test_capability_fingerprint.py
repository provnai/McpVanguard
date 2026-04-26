from core import capability_fingerprint, signing


def test_build_capability_manifest_fingerprints_initialize_and_tools():
    manifest = capability_fingerprint.build_capability_manifest(
        initialize_payload={
            "jsonrpc": "2.0",
            "id": "init-1",
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "demo", "version": "1.0.0"},
                "instructions": "Use the tools responsibly.",
            },
        },
        tools_payload={
            "jsonrpc": "2.0",
            "id": "tools-1",
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file.",
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
        },
    )

    assert manifest["initialize"]["protocolVersion"] == "2025-03-26"
    assert manifest["tools"]["count"] == 1
    assert manifest["tools"]["tools"][0]["name"] == "read_file"


def test_compare_capability_manifests_detects_tool_drift():
    expected = capability_fingerprint.build_capability_manifest(
        tools_payload={
            "jsonrpc": "2.0",
            "id": "tools-1",
            "result": {"tools": [{"name": "read_file", "description": "Read a file."}]},
        }
    )
    actual = capability_fingerprint.build_capability_manifest(
        tools_payload={
            "jsonrpc": "2.0",
            "id": "tools-1",
            "result": {"tools": [{"name": "write_file", "description": "Write a file."}]},
        }
    )

    drifts = capability_fingerprint.compare_capability_manifests(expected, actual)

    assert "tools" in drifts


def test_sign_and_verify_capability_manifest_round_trip(tmp_path):
    manifest = capability_fingerprint.build_capability_manifest(
        tools_payload={
            "jsonrpc": "2.0",
            "id": "tools-1",
            "result": {"tools": [{"name": "read_file", "description": "Read a file."}]},
        }
    )
    private_key_pem, signer_doc = signing.generate_signing_keypair("capability-signer")
    signature_doc = capability_fingerprint.sign_capability_manifest(
        manifest,
        private_key_pem,
        signer_doc["key_id"],
    )
    trusted_signers = capability_fingerprint.load_trusted_capability_signers(extra_signers=[signer_doc])

    capability_fingerprint.verify_capability_manifest_signature(
        manifest,
        signature_doc,
        trusted_signers,
    )


def test_evaluate_capability_manifest_signature_detects_tampering(tmp_path):
    manifest = capability_fingerprint.build_capability_manifest(
        tools_payload={
            "jsonrpc": "2.0",
            "id": "tools-1",
            "result": {"tools": [{"name": "read_file", "description": "Read a file."}]},
        }
    )
    private_key_pem, signer_doc = signing.generate_signing_keypair("capability-signer")
    signature_doc = capability_fingerprint.sign_capability_manifest(
        manifest,
        private_key_pem,
        signer_doc["key_id"],
    )
    manifest["tools"]["tools"][0]["inputSchema_sha256"] = "tampered"
    trusted_signers = capability_fingerprint.load_trusted_capability_signers(extra_signers=[signer_doc])

    issues = capability_fingerprint.evaluate_capability_manifest_signature(
        manifest,
        signature_doc=signature_doc,
        trusted_signers=trusted_signers,
        require_signature=True,
    )

    assert issues
    assert "verification failed" in issues[0].lower() or "digest" in issues[0].lower()
