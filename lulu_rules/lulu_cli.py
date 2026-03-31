"""Thin subprocess wrapper around the lulu-cli binary.

Only used for reload and presence detection. Rule add/remove is handled
by plist_writer.py (the compiled Swift helper) which does a single
plist read-modify-write for the whole batch.
"""

from __future__ import annotations

import logging
import os
import subprocess

logger = logging.getLogger(__name__)

MANAGED_KEY = "com.lulu-rules.c2-feeds"

_CANDIDATE_PATHS = [
    "/usr/local/bin/lulu-cli",
    "/opt/homebrew/bin/lulu-cli",
    os.path.expanduser("~/.local/bin/lulu-cli"),
]


def find_lulu_cli() -> str | None:
    """Return the path to the lulu-cli binary, or None if not found."""
    for path in _CANDIDATE_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _run(args: list[str], lulu_cli_path: str) -> tuple[int, str, str]:
    """Run a lulu-cli command. Returns (returncode, stdout, stderr)."""
    cmd = [lulu_cli_path] + args
    logger.debug("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.stderr:
            logger.debug("lulu-cli stderr: %s", result.stderr.strip())
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error("lulu-cli timed out: %s", " ".join(cmd))
        return -1, "", "timeout"
    except OSError as exc:
        logger.error("Failed to run lulu-cli: %s", exc)
        return -1, "", str(exc)


def reload_lulu(lulu_cli_path: str) -> bool:
    """Reload the LuLu system extension to apply rule changes (~8s gap in filtering)."""
    logger.info("Reloading LuLu extension (brief ~8s gap in filtering)...")
    rc, _, stderr = _run(["reload"], lulu_cli_path)
    if rc != 0:
        logger.error("Failed to reload LuLu (exit %d): %s", rc, stderr.strip())
        return False
    logger.info("LuLu reloaded.")
    return True


def is_lulu_running() -> bool:
    """Return True if the LuLu system extension process is running."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "com.objective-see.lulu"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
