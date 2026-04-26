"""
core/session_isolation.py
Cross-server identity resolution and boundary-check helpers.

Provides a stable, deterministic fingerprint for the upstream MCP server
command so that behavioral state and session tracking can be partitioned
per upstream server identity — even within a single long-lived proxy session.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from core.session import SessionState

logger = logging.getLogger("vanguard.session_isolation")

# Length of the short hex fingerprint used as server_id.
# 12 hex chars = 48 bits — collision probability is negligible for any
# realistic number of distinct server commands in one deployment.
_SERVER_ID_LENGTH = 12


def derive_server_id(server_command: list[str]) -> str:
    """
    Derive a stable, deterministic server identity string from the command argv.

    The result is a short (12-char) lowercase hex string that is:
    - Stable: same command always produces the same ID across restarts.
    - Unique:  distinct commands produce distinct IDs with overwhelming probability.
    - Opaque:  does not leak the full command into audit log field values.

    Example:
        derive_server_id(["npx", "@modelcontextprotocol/server-filesystem", "."])
        # → "3a7f91bc04e2"
    """
    if not server_command:
        return "unknown"
    canonical = json.dumps(server_command, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest[:_SERVER_ID_LENGTH]


@dataclass(frozen=True)
class CrossServerTransitionEvent:
    """
    Emitted when a proxy session is contacted by a server_id different from
    the one that originally created the session.

    In current single-upstream deployments this never fires.
    In future multi-upstream gateways it marks a trust-boundary crossing
    that must be made visible in the audit log.
    """
    session_id: str
    original_server_id: Optional[str]
    incoming_server_id: str

    def to_log_string(self) -> str:
        return (
            f"[CROSS-SERVER] session={self.session_id} "
            f"original_server={self.original_server_id or 'none'} "
            f"incoming_server={self.incoming_server_id}"
        )


def check_server_boundary(
    session: "SessionState",
    incoming_server_id: str,
) -> Optional[CrossServerTransitionEvent]:
    """
    Compare the incoming server_id against the session's recorded server_id.

    Returns a CrossServerTransitionEvent if they differ (a boundary crossing),
    or None if they match (normal single-upstream operation).
    """
    original = session.server_id
    if original is None or original == incoming_server_id:
        return None

    event = CrossServerTransitionEvent(
        session_id=session.session_id,
        original_server_id=original,
        incoming_server_id=incoming_server_id,
    )
    logger.warning(event.to_log_string())
    return event
