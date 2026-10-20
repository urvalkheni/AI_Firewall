"""Target Resource Precondition Verifier for AI Firewall Execution Broker.

Supports:
- Tier 1: Atomic conditional targets (e.g., HTTP ETag matching via If-Match).
- Tier 2: Inspectable targets (e.g., SHA-256 file content hash revalidation).
- Tier 3: Unchecked targets (raises informative warning/limitation in audit log).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import os
from typing import Any, Callable, Optional


class PreconditionMode(str, Enum):
    """Supported precondition modes."""

    EXACT_ETAG_MATCH = "EXACT_ETAG_MATCH"
    EXACT_HASH_MATCH = "EXACT_HASH_MATCH"
    MODE_UNCHECKED = "MODE_UNCHECKED"


class PreconditionCheckError(Exception):
    """Base error for precondition verification failures."""


class StateDriftError(PreconditionCheckError):
    """Raised when the live resource state deviates from the approved precondition (TOCTOU)."""


@dataclass(frozen=True)
class PreconditionResult:
    """Outcome of a pre-dispatch resource inspection."""

    passed: bool
    mode: PreconditionMode
    expected_value: Optional[str]
    actual_value: Optional[str]
    message: str


def verify_resource_preconditions(
    resource_uri: str,
    preconditions: Optional[dict[str, Any]],
    live_state_inspector: Optional[Callable[[str], dict[str, Any]]] = None,
) -> PreconditionResult:
    """Verifies that the target resource state matches the approved preconditions.

    Args:
        resource_uri: The target URI (e.g., 'file:///tmp/test.txt' or 'http://...').
        preconditions: Preconditions dictionary containing expected_etag or expected_sha256.
        live_state_inspector: Injected mock/real inspector callable returning live metadata
            (e.g., {'etag': '...', 'sha256': '...'}). If None, uses default file inspector.

    Returns:
        PreconditionResult summarizing check outcome.

    Raises:
        StateDriftError: If live state does not match expected preconditions.
    """
    if preconditions is None:
        return PreconditionResult(
            passed=True,
            mode=PreconditionMode.MODE_UNCHECKED,
            expected_value=None,
            actual_value=None,
            message="No preconditions declared on action; execution proceeds unchecked",
        )

    mode_str = preconditions.get("precondition_mode", "EXACT_HASH_MATCH")
    try:
        mode = PreconditionMode(mode_str)
    except ValueError:
        mode = PreconditionMode.EXACT_HASH_MATCH

    # Get live state via inspector if provided
    if live_state_inspector is not None:
        live_metadata = live_state_inspector(resource_uri)
    else:
        # Default local file state inspector
        if resource_uri.startswith("file://"):
            local_path = resource_uri[7:]
            if os.path.exists(local_path):
                with open(local_path, "rb") as f:
                    content = f.read()
                live_metadata = {
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "etag": f'W/"{len(content)}-{int(os.path.getmtime(local_path))}"',
                }
            else:
                live_metadata = {"sha256": None, "etag": None, "exists": False}
        else:
            # Fallback for uninspectable targets
            live_metadata = {}

    # 1. Check ETag if mode is EXACT_ETAG_MATCH or expected_etag present
    expected_etag = preconditions.get("expected_etag")
    if expected_etag:
        actual_etag = live_metadata.get("etag")
        if actual_etag != expected_etag:
            raise StateDriftError(
                f"State drift detected! Expected ETag {expected_etag!r}, but live resource has {actual_etag!r}"
            )
        return PreconditionResult(
            passed=True,
            mode=PreconditionMode.EXACT_ETAG_MATCH,
            expected_value=expected_etag,
            actual_value=actual_etag,
            message="Live ETag matches approved precondition",
        )

    # 2. Check SHA-256 hash
    expected_sha256 = preconditions.get("expected_sha256")
    if expected_sha256:
        actual_sha256 = live_metadata.get("sha256")
        if actual_sha256 != expected_sha256:
            raise StateDriftError(
                f"State drift detected! Expected SHA-256 {expected_sha256!r}, but live resource has {actual_sha256!r}"
            )
        return PreconditionResult(
            passed=True,
            mode=PreconditionMode.EXACT_HASH_MATCH,
            expected_value=expected_sha256,
            actual_value=actual_sha256,
            message="Live SHA-256 hash matches approved precondition",
        )

    return PreconditionResult(
        passed=True,
        mode=PreconditionMode.MODE_UNCHECKED,
        expected_value=None,
        actual_value=None,
        message="Preconditions object contained no expected_etag or expected_sha256 values",
    )

