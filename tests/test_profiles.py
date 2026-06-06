"""
tests/test_profiles.py — Unit tests for the named deployment profiles module.
"""

import os
import pytest
from dataclasses import FrozenInstanceError
from unittest.mock import patch, MagicMock

from core.profiles import (
    resolve_profile,
    warn_strict_redis_if_needed,
    profile_startup_summary,
    PROFILES,
    MONITOR,
    BALANCED,
    STRICT,
    ProfileDefaults,
    ProfileName,
)
from core.proxy import ProxyConfig, VanguardProxy


def test_profile_immutability():
    """Ensure that all profile configurations are frozen and immutable."""
    for profile in PROFILES.values():
        with pytest.raises(FrozenInstanceError):
            profile.mode = "audit"
        with pytest.raises(FrozenInstanceError):
            profile.semantic_enabled = not profile.semantic_enabled


def test_profile_defaults():
    """Verify that singleton profiles match the specifications exactly."""
    # Monitor Profile
    assert MONITOR.name == "monitor"
    assert MONITOR.mode == "audit"
    assert MONITOR.default_policy == "ALLOW"
    assert MONITOR.semantic_enabled is False
    assert MONITOR.semantic_fail_closed is False
    assert MONITOR.semantic_threshold_warn == 0.50
    assert MONITOR.semantic_threshold_block == 0.80
    assert MONITOR.behavioral_enabled is True
    assert MONITOR.metadata_policy == "warn"
    assert MONITOR.block_enumeration is False
    assert MONITOR.strict_redis_warn is False

    # Balanced Profile
    assert BALANCED.name == "balanced"
    assert BALANCED.mode == "enforce"
    assert BALANCED.default_policy == "ALLOW"
    assert BALANCED.semantic_enabled is False
    assert BALANCED.semantic_fail_closed is True
    assert BALANCED.semantic_threshold_warn == 0.50
    assert BALANCED.semantic_threshold_block == 0.80
    assert BALANCED.behavioral_enabled is True
    assert BALANCED.metadata_policy == "block"
    assert BALANCED.block_enumeration is False
    assert BALANCED.strict_redis_warn is False

    # Strict Profile
    assert STRICT.name == "strict"
    assert STRICT.mode == "enforce"
    assert STRICT.default_policy == "ALLOW"
    assert STRICT.semantic_enabled is True
    assert STRICT.semantic_fail_closed is True
    assert STRICT.semantic_threshold_warn == 0.40
    assert STRICT.semantic_threshold_block == 0.80
    assert STRICT.behavioral_enabled is True
    assert STRICT.metadata_policy == "block"
    assert STRICT.block_enumeration is True
    assert STRICT.strict_redis_warn is True


def test_resolve_profile_no_overrides():
    """resolve_profile should return all fields if they are absent from the env."""
    empty_env = {}
    
    # Monitor
    overrides = resolve_profile("monitor", empty_env)
    assert overrides["mode"] == "audit"
    assert overrides["semantic_enabled"] is False
    assert overrides["warn_threshold"] == 0.50
    assert overrides["block_threshold"] == 0.80
    assert overrides["default_policy"] == "ALLOW"
    assert overrides["block_enumeration"] is False

    # Strict
    overrides = resolve_profile("strict", empty_env)
    assert overrides["mode"] == "enforce"
    assert overrides["semantic_enabled"] is True
    assert overrides["warn_threshold"] == 0.40
    assert overrides["block_threshold"] == 0.80
    assert overrides["default_policy"] == "ALLOW"
    assert overrides["block_enumeration"] is True


def test_resolve_profile_with_overrides():
    """resolve_profile must respect explicit env vars and only supply defaults for absent ones."""
    env = {
        "VANGUARD_MODE": "audit",
        "VANGUARD_SEMANTIC_ENABLED": "false",
        "VANGUARD_SEMANTIC_THRESHOLD_WARN": "0.15",
    }
    
    # We resolve strict profile, but with VANGUARD_SEMANTIC_ENABLED set to false,
    # it should not be in the returned overrides (meaning the proxy config will keep the env-derived value).
    overrides = resolve_profile("strict", env)
    
    # These were present in env, so they should NOT be in the overrides dict
    assert "mode" not in overrides
    assert "semantic_enabled" not in overrides
    assert "warn_threshold" not in overrides
    
    # These were NOT present in env, so they should be resolved to their strict defaults
    assert overrides["block_threshold"] == 0.80
    assert overrides["semantic_fail_closed"] is True
    assert overrides["block_enumeration"] is True


def test_resolve_profile_invalid_name():
    """resolve_profile should raise ValueError for unknown profiles."""
    with pytest.raises(ValueError) as exc:
        resolve_profile("invalid-profile-name", {})
    assert "Unknown VANGUARD_PROFILE" in str(exc.value)


def test_warn_strict_redis_if_needed():
    """Verify that warnings are only emitted when strict profile is used and Redis is absent."""
    with patch("core.profiles.logger.warning") as mock_warn:
        # Balanced profile — no warning regardless of Redis
        warn_strict_redis_if_needed("balanced", None)
        mock_warn.assert_not_called()

        # Strict profile with Redis configured — no warning
        warn_strict_redis_if_needed("strict", "redis://localhost:6379")
        mock_warn.assert_not_called()

        # Strict profile without Redis — warning is logged
        warn_strict_redis_if_needed("strict", None)
        mock_warn.assert_called_once()
        assert "REDIS NOT CONFIGURED" in mock_warn.call_args[0][0]


def test_profile_startup_summary():
    """Verify formatting of profile startup summary lines."""
    overrides = {
        "mode": "enforce",
        "semantic_enabled": True,
        "behavioral_enabled": True,
        "metadata_policy": "block",
        "block_enumeration": True,
    }
    summary = profile_startup_summary("strict", overrides)
    assert "Profile: strict" in summary
    assert "mode=enforce" in summary
    assert "semantic=ON" in summary
    assert "behavioral=ON" in summary
    assert "metadata_policy=block" in summary
    assert "enumeration_block=ON" in summary


def test_proxy_config_profile_integration():
    """Test that ProxyConfig parses VANGUARD_PROFILE and resolves overrides correctly."""
    # Test strict profile defaults loaded correctly
    with patch.dict(
        os.environ,
        {
            "VANGUARD_PROFILE": "strict",
            "VANGUARD_SEMANTIC_ENABLED": "true",
        },
    ):
        config = ProxyConfig()
        assert config.profile == "strict"
        assert config.mode == "enforce"
        assert config.semantic_enabled is True
        assert config.block_enumeration is True
        assert config.semantic_fail_closed is True

    # Test explicit env vars winning over strict profile
    with patch.dict(
        os.environ,
        {
            "VANGUARD_PROFILE": "strict",
            "VANGUARD_SEMANTIC_ENABLED": "false",
            "VANGUARD_BLOCK_ENUMERATION": "false",
        },
    ):
        config = ProxyConfig()
        assert config.profile == "strict"
        assert config.semantic_enabled is False
        assert config.block_enumeration is False
        assert config.semantic_fail_closed is True  # still strict default because not in env


@pytest.mark.asyncio
async def test_proxy_profile_rule_reload_does_not_leak_strict_overlay():
    """Strict-only rules must not leak into later balanced proxies in-process."""
    strict_only_message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {"command": "unset HISTFILE; echo done"},
        },
    }

    with patch.dict(
        os.environ,
        {"VANGUARD_PROFILE": "strict", "VANGUARD_SEMANTIC_ENABLED": "false"},
        clear=False,
    ):
        strict_proxy = VanguardProxy(server_command=["python", "-c", "print('noop')"])
        strict_result = await strict_proxy._inspect_message(strict_only_message)

    assert strict_result.action == "BLOCK"
    assert strict_result.rule_matches[0].rule_id == "STRICT-AF-001"

    with patch.dict(
        os.environ,
        {"VANGUARD_PROFILE": "balanced", "VANGUARD_SEMANTIC_ENABLED": "false"},
        clear=False,
    ):
        balanced_proxy = VanguardProxy(server_command=["python", "-c", "print('noop')"])
        balanced_result = await balanced_proxy._inspect_message(strict_only_message)

    assert balanced_result.action == "ALLOW"
