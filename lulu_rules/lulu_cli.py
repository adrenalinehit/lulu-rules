"""Thin subprocess wrapper around the lulu-cli binary."""

import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

# The key used for all feed-managed block rules.
# Using a unique key isolates these rules from any user-created rules.
MANAGED_KEY = "com.lulu-rules.c2-feeds"
MANAGED_PATH = "*"  # Endpoint-scoped — applies regardless of which app initiates traffic

_CANDIDATE_PATHS = [
    "/usr/local/bin/lulu-cli",
    "/opt/homebrew/bin/lulu-cli",
    os.path.expanduser("~/.local/bin/lulu-cli"),
]

# Pattern to extract UUID from lulu-cli add output, e.g.:
# "Added rule AAAA-BBBB-CCCC-DDDD-EEEE for com.lulu-rules.c2-feeds: Block 1.2.3.4:*"
_UUID_RE = re.compile(r'[Aa]dded rule\s+([A-Fa-f0-9\-]{36})', re.IGNORECASE)


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


def add_rule(indicator: str, lulu_cli_path: str) -> str | None:
    """
    Add a block rule for the given indicator (IP or domain).
    Returns the UUID string assigned by lulu-cli, or None on failure.
    """
    rc, stdout, stderr = _run(
        [
            "add",
            "--key", MANAGED_KEY,
            "--path", MANAGED_PATH,
            "--action", "block",
            "--addr", indicator,
            "--port", "*",
        ],
        lulu_cli_path,
    )
    if rc != 0:
        logger.warning(
            "Failed to add rule for %r (exit %d): %s", indicator, rc, stderr.strip()
        )
        return None
    match = _UUID_RE.search(stdout)
    if not match:
        logger.warning(
            "Added rule for %r but could not parse UUID from output: %r",
            indicator,
            stdout.strip(),
        )
        return None
    uuid = match.group(1)
    logger.debug("Added rule for %r → UUID %s", indicator, uuid)
    return uuid


def remove_rule(uuid: str, lulu_cli_path: str) -> bool:
    """Delete a specific rule by UUID. Returns True on success."""
    rc, _, stderr = _run(
        ["delete", "--key", MANAGED_KEY, "--uuid", uuid],
        lulu_cli_path,
    )
    if rc != 0:
        logger.warning(
            "Failed to delete rule UUID %s (exit %d): %s", uuid, rc, stderr.strip()
        )
        return False
    logger.debug("Deleted rule UUID %s", uuid)
    return True


def remove_all_managed_rules(lulu_cli_path: str) -> bool:
    """Delete ALL rules under the managed key. Used for --force-rebuild."""
    rc, _, stderr = _run(
        ["delete", "--key", MANAGED_KEY],
        lulu_cli_path,
    )
    if rc != 0:
        logger.error(
            "Failed to delete all managed rules (exit %d): %s", rc, stderr.strip()
        )
        return False
    logger.info("Deleted all managed rules (key=%s).", MANAGED_KEY)
    return True


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
