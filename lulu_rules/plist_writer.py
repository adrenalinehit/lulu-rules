"""
Batch rule writer for LuLu's rules.plist.

Calls the compiled Swift helper (lulu-rules-helper) which performs a single
plist read-modify-write for the entire batch rather than one per indicator.
This reduces O(n²) plist I/O to O(1) regardless of how many rules change.
"""

import json
import logging
import os
import subprocess
import uuid

logger = logging.getLogger(__name__)

HELPER_PATH = "/usr/local/lib/lulu-rules/lulu-rules-helper"


def find_helper() -> str | None:
    """Return the path to the compiled Swift helper, or None if not installed."""
    if os.path.isfile(HELPER_PATH) and os.access(HELPER_PATH, os.X_OK):
        return HELPER_PATH
    return None


def batch_apply(
    to_add: set,
    to_remove_uuids: set,
    clear_managed: bool = False,
) -> dict[str, str]:
    """
    Apply all rule changes in a single plist read-modify-write.

    Args:
        to_add:           Set of indicator strings (IPs, CIDRs, domains) to add.
        to_remove_uuids:  Set of UUID strings for rules to remove.
        clear_managed:    If True, wipe all existing managed rules before adding
                          (used for --force-rebuild).

    Returns:
        Dict of {indicator: uuid} for every newly added rule.

    Raises:
        RuntimeError if the helper is not found or exits non-zero.
    """
    helper = find_helper()
    if helper is None:
        raise RuntimeError(
            f"lulu-rules-helper not found at {HELPER_PATH}. "
            "Re-run install.sh to compile it."
        )

    # Pre-generate UUIDs in Python so state.json knows them before the helper runs.
    add_entries = [
        {"addr": indicator, "uuid": str(uuid.uuid4()).upper()}
        for indicator in sorted(to_add)
    ]

    payload = {
        "add": add_entries,
        "remove": list(to_remove_uuids),
        "clear_managed": clear_managed,
    }

    logger.debug(
        "plist_writer: add=%d remove=%d clear_managed=%s",
        len(add_entries),
        len(to_remove_uuids),
        clear_managed,
    )

    try:
        result = subprocess.run(
            [helper],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("lulu-rules-helper timed out after 120 seconds")
    except OSError as exc:
        raise RuntimeError(f"Failed to launch lulu-rules-helper: {exc}") from exc

    if result.stderr:
        logger.warning("lulu-rules-helper: %s", result.stderr.strip())

    if result.returncode != 0:
        raise RuntimeError(
            f"lulu-rules-helper exited {result.returncode}: {result.stderr.strip()}"
        )

    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(
            f"lulu-rules-helper returned non-JSON output: {result.stdout!r}"
        )

    if not response.get("ok"):
        raise RuntimeError(f"lulu-rules-helper reported failure: {response}")

    logger.info(
        "plist_writer: wrote %d rules to plist (added %d, removed %d).",
        response.get("added", 0),
        response.get("added", 0),
        response.get("removed", 0),
    )

    return {entry["addr"]: entry["uuid"] for entry in add_entries}
