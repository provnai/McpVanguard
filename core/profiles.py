"""
core/profiles.py
McpVanguard named deployment profiles.

Profiles are immutable configuration presets that establish safe defaults
for three distinct deployment contexts:

  monitor  — discovery, pilot rollout, developer adoption. Never blocks.
  balanced — default OSS / developer-facing behavior. Blocks high-confidence threats.
  strict   — production agents touching sensitive systems. Maximum enforcement.

Usage:
    from core.profiles import resolve_profile, PROFILES, ProfileName

    # Resolve profile from name + current environment
    overrides = resolve_profile("strict", os.environ)

    # overrides is a dict[str, Any] mapping ProxyConfig attribute names to values.
    # Explicit env vars always win; profile defaults only fill gaps.

Design invariants:
    - Profile dataclasses are frozen — no mutation after construction.
    - Profile defaults are NEVER applied on top of an explicit env var.
      resolve_profile() only returns values for env vars that are absent.
    - No external I/O inside this module (no file reads, no network).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Profile name enumeration
# ---------------------------------------------------------------------------


class ProfileName(str, Enum):
    MONITOR = "monitor"
    BALANCED = "balanced"
    STRICT = "strict"


# ---------------------------------------------------------------------------
# Profile defaults dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProfileDefaults:
    """
    Immutable set of default ProxyConfig values for a named profile.

    Each field maps exactly to a ``ProxyConfig`` attribute name and the
    environment variable that controls it.  Only fields listed here are
    candidates for profile-driven defaults; all other ProxyConfig values
    are untouched.

    Fields use their ProxyConfig Python types (bool, str, float) — not
    the string form used by env vars.  ``resolve_profile`` handles the
    conversion.
    """
    name: str

    # --- Mode & enforcement ---
    mode: str = "enforce"                        # VANGUARD_MODE
    default_policy: str = "ALLOW"                # VANGUARD_DEFAULT_POLICY

    # --- Semantic (L2) ---
    semantic_enabled: bool = False               # VANGUARD_SEMANTIC_ENABLED
    semantic_fail_closed: bool = False           # VANGUARD_SEMANTIC_FAIL_CLOSED
    semantic_threshold_warn: float = 0.50        # VANGUARD_SEMANTIC_THRESHOLD_WARN  (→ warn_threshold)
    semantic_threshold_block: float = 0.80       # VANGUARD_SEMANTIC_THRESHOLD_BLOCK (→ block_threshold)

    # --- Behavioral (L3) ---
    behavioral_enabled: bool = True              # VANGUARD_BEHAVIORAL_ENABLED

    # --- Metadata ---
    metadata_policy: str = "block"              # VANGUARD_METADATA_POLICY

    # --- Enumeration blocking ---
    block_enumeration: bool = False             # VANGUARD_BLOCK_ENUMERATION

    # --- Redis (strict-only) ---
    strict_redis_warn: bool = False             # internal flag: warn when Redis absent in strict mode


# ---------------------------------------------------------------------------
# Concrete profile singletons
# ---------------------------------------------------------------------------


MONITOR = ProfileDefaults(
    name=ProfileName.MONITOR.value,
    mode="audit",
    default_policy="ALLOW",
    semantic_enabled=False,
    semantic_fail_closed=False,
    semantic_threshold_warn=0.50,
    semantic_threshold_block=0.80,
    behavioral_enabled=True,
    metadata_policy="warn",
    block_enumeration=False,
    strict_redis_warn=False,
)

BALANCED = ProfileDefaults(
    name=ProfileName.BALANCED.value,
    mode="enforce",
    default_policy="ALLOW",
    semantic_enabled=False,
    semantic_fail_closed=True,
    semantic_threshold_warn=0.50,
    semantic_threshold_block=0.80,
    behavioral_enabled=True,
    metadata_policy="block",
    block_enumeration=False,
    strict_redis_warn=False,
)

STRICT = ProfileDefaults(
    name=ProfileName.STRICT.value,
    mode="enforce",
    default_policy="ALLOW",
    semantic_enabled=True,
    semantic_fail_closed=True,
    semantic_threshold_warn=0.40,
    semantic_threshold_block=0.80,   # finalize after benchmark sweep
    behavioral_enabled=True,
    metadata_policy="block",
    block_enumeration=True,
    strict_redis_warn=True,
)

# Registry — all valid profile names map here.
PROFILES: dict[str, ProfileDefaults] = {
    ProfileName.MONITOR.value: MONITOR,
    ProfileName.BALANCED.value: BALANCED,
    ProfileName.STRICT.value: STRICT,
}


# ---------------------------------------------------------------------------
# Env-var → ProfileDefaults field mapping
# ---------------------------------------------------------------------------

# Maps env var names to profile field names and coercion functions.
# coerce_fn converts the string env value to the Python type expected by ProxyConfig.
_ENV_TO_FIELD: dict[str, tuple[str, Any]] = {
    "VANGUARD_MODE": ("mode", str),
    "VANGUARD_SEMANTIC_ENABLED": ("semantic_enabled", lambda v: v.lower() == "true"),
    "VANGUARD_SEMANTIC_FAIL_CLOSED": ("semantic_fail_closed", lambda v: v.lower() == "true"),
    "VANGUARD_SEMANTIC_THRESHOLD_WARN": ("semantic_threshold_warn", float),
    "VANGUARD_SEMANTIC_THRESHOLD_BLOCK": ("semantic_threshold_block", float),
    "VANGUARD_BEHAVIORAL_ENABLED": ("behavioral_enabled", lambda v: v.lower() == "true"),
    "VANGUARD_METADATA_POLICY": ("metadata_policy", str),
    "VANGUARD_BLOCK_ENUMERATION": ("block_enumeration", lambda v: v.lower() == "true"),
    "VANGUARD_DEFAULT_POLICY": ("default_policy", str),
}

# Maps profile field names to ProxyConfig attribute names where they differ.
_FIELD_TO_PROXY_ATTR: dict[str, str] = {
    "semantic_threshold_warn": "warn_threshold",
    "semantic_threshold_block": "block_threshold",
    "semantic_fail_closed": "semantic_fail_closed",
    "default_policy": "default_policy",
    "block_enumeration": "block_enumeration",
}


def _proxy_attr(field_name: str) -> str:
    """Return the ProxyConfig attribute name for a given profile field name."""
    return _FIELD_TO_PROXY_ATTR.get(field_name, field_name)


# ---------------------------------------------------------------------------
# resolve_profile()
# ---------------------------------------------------------------------------


def resolve_profile(
    profile_name: str,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Return a ``dict[proxy_attr → value]`` of profile defaults that are not
    already overridden by an explicit environment variable.

    The caller (ProxyConfig.__init__) should apply these values AFTER
    reading any env vars but BEFORE returning the config object.  Explicit
    env vars always take priority.

    Args:
        profile_name:  One of "monitor", "balanced", "strict".
        env:           Environment mapping (defaults to ``os.environ``).

    Returns:
        A plain dict of ``{ proxy_config_attribute_name: value }`` pairs
        representing the *effective* profile defaults after honouring any
        explicit env-var overrides.

    Raises:
        ValueError: if ``profile_name`` is not a known profile.
    """
    if env is None:
        env = dict(os.environ)

    name_lower = profile_name.strip().lower()
    profile = PROFILES.get(name_lower)
    if profile is None:
        known = ", ".join(PROFILES.keys())
        raise ValueError(
            f"Unknown VANGUARD_PROFILE '{profile_name}'. "
            f"Valid values: {known}"
        )

    overrides: dict[str, Any] = {}

    for env_var, (field_name, coerce) in _ENV_TO_FIELD.items():
        # If the operator has explicitly set this env var, skip — env wins.
        if env_var in env and env[env_var].strip():
            continue

        profile_value = getattr(profile, field_name)
        proxy_attr = _proxy_attr(field_name)
        overrides[proxy_attr] = profile_value

    return overrides


# ---------------------------------------------------------------------------
# Redis warning helper
# ---------------------------------------------------------------------------


def warn_strict_redis_if_needed(profile_name: str, redis_url: str | None) -> None:
    """
    Emit a loud startup warning when the strict profile is active but no
    Redis URL has been configured.  Multi-instance behavioral enforcement
    (L3) is silently degraded to single-instance in-process state without Redis.

    This is called once during proxy startup.
    """
    name_lower = (profile_name or "").strip().lower()
    profile = PROFILES.get(name_lower)
    if profile is None or not profile.strict_redis_warn:
        return

    if redis_url:
        return  # Redis is configured, no warning needed.

    logger.warning(
        "[Vanguard][strict-profile] REDIS NOT CONFIGURED — behavioral and risk state "
        "is SINGLE-INSTANCE ONLY and will NOT be shared across replicas. "
        "Set VANGUARD_REDIS_URL for multi-instance strict deployments. "
        "See docs/DEPLOYMENT.md for details."
    )


# ---------------------------------------------------------------------------
# Profile summary for startup log
# ---------------------------------------------------------------------------


def profile_startup_summary(profile_name: str, applied_overrides: dict[str, Any]) -> str:
    """
    Return a human-readable single-line summary of the active profile for
    the startup banner.

    Example:
        "[Vanguard] Profile: strict | mode=enforce semantic=ON behavioral=ON ..."
    """
    name_lower = (profile_name or "balanced").strip().lower()
    parts = [f"Profile: {name_lower}"]

    # Always show a few key flags regardless of overrides
    show_attrs = [
        ("mode", "mode"),
        ("semantic_enabled", "semantic"),
        ("behavioral_enabled", "behavioral"),
        ("metadata_policy", "metadata_policy"),
        ("block_enumeration", "enumeration_block"),
    ]

    profile = PROFILES.get(name_lower, BALANCED)
    for field_name, label in show_attrs:
        proxy_attr = _proxy_attr(field_name)
        # Use applied_overrides first (profile default), then profile field
        value = applied_overrides.get(proxy_attr, getattr(profile, field_name))
        if isinstance(value, bool):
            value = "ON" if value else "OFF"
        parts.append(f"{label}={value}")

    return "[Vanguard] " + " | ".join(parts)
