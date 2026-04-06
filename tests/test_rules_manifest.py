import hashlib
import json
from pathlib import Path

from core import signing


def test_rules_manifest_matches_rule_files():
    rules_dir = Path("rules")
    manifest = json.loads((rules_dir / "manifest.json").read_text(encoding="utf-8"))

    for filename, entry in manifest["rules"].items():
        content = (rules_dir / filename).read_text(encoding="utf-8")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert digest == entry["sha256"], f"Manifest hash mismatch for {filename}"


def test_rules_manifest_signature_verifies():
    rules_dir = Path("rules")
    manifest = json.loads((rules_dir / "manifest.json").read_text(encoding="utf-8"))
    signature_doc = json.loads((rules_dir / "manifest.sig.json").read_text(encoding="utf-8"))

    signing.verify_manifest_signature(
        manifest,
        signature_doc,
        trusted_signers=signing.load_trusted_signers(),
    )
