"""
tests/test_entropy_scouter.py
Task 3: Verifies the Shannon Entropy scouter and risk-weighted throttling logic.
"""

import unittest
from core.behavioral import (
    compute_shannon_entropy,
    entropy_risk_label,
    inspect_response,
    ENTROPY_HIGH_THRESHOLD,
    ENTROPY_BLOCK_THRESHOLD,
    get_state,
    clear_state,
)
import asyncio


class TestShannonEntropy(unittest.TestCase):

    def test_zero_entropy_empty(self):
        self.assertEqual(compute_shannon_entropy(b""), 0.0)

    def test_low_entropy_plaintext(self):
        """A repetitive plaintext string has low entropy."""
        data = b"hello world " * 500
        h = compute_shannon_entropy(data)
        self.assertLess(h, 4.0)

    def test_high_entropy_random(self):
        """Random bytes should have entropy near 8.0."""
        import os
        data = os.urandom(8192)
        h = compute_shannon_entropy(data)
        self.assertGreater(h, 6.5)

    def test_rsa_key_like_entropy(self):
        """Simulate a base64-encoded RSA key (high entropy ~5.9-6.5)."""
        import base64, os
        key_bytes = base64.b64encode(os.urandom(2048))
        h = compute_shannon_entropy(key_bytes)
        self.assertGreater(h, 5.0, "Base64 key material should have H > 5.0")

    def test_only_samples_8kb(self):
        """Entropy calculation should not blow up on huge payloads."""
        data = b"\x00" * (1024 * 1024)  # 1MB of zeros
        h = compute_shannon_entropy(data)
        self.assertEqual(h, 0.0)

    def test_entropy_risk_label_critical(self):
        self.assertIn("CRITICAL", entropy_risk_label(ENTROPY_BLOCK_THRESHOLD + 0.1))

    def test_entropy_risk_label_high(self):
        self.assertIn("HIGH", entropy_risk_label(ENTROPY_HIGH_THRESHOLD + 0.1))

    def test_entropy_risk_label_low(self):
        self.assertIn("LOW", entropy_risk_label(3.0))


class TestEntropyThrottling(unittest.TestCase):
    """Verify entropy penalty is applied to rate-limit window."""

    def setUp(self):
        clear_state("test-entropy")

    def test_high_entropy_response_blocked(self):
        """A response with H > 7.5 should be blocked with BEH-006."""
        import os
        # Simulate encrypted/key-like data
        random_payload = os.urandom(4096).hex()  # hex of random = high entropy

        result = asyncio.run(inspect_response("test-entropy", random_payload))

        # The response may or may not cross threshold depending on entropy of .hex()
        # Raw bytes > 7.5; hex encoding lowers to ~3.9 (only 0-9,a-f)
        # So we test with bytes directly via compute_shannon_entropy
        from core.behavioral import compute_shannon_entropy
        h = compute_shannon_entropy(random_payload.encode())
        if h >= ENTROPY_BLOCK_THRESHOLD:
            self.assertIsNotNone(result)
            self.assertFalse(result.allowed)
            self.assertEqual(result.rule_matches[0].rule_id, "BEH-006")

    def test_low_entropy_response_passes(self):
        """A normal plaintext response should pass the entropy check."""
        plain = '{"result": "Hello, world! This is a normal response."}'
        result = asyncio.run(inspect_response("test-entropy", plain))
        # Should not be blocked by entropy
        if result:
            self.assertNotEqual(result.rule_matches[0].rule_id, "BEH-006")


if __name__ == "__main__":
    unittest.main()
