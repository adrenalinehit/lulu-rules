"""Manages the persistent state file that tracks which indicators are currently
applied to LuLu and their associated lulu-cli UUIDs."""

import json
import logging
import os
from datetime import datetime, timezone

STATE_VERSION = 1
logger = logging.getLogger(__name__)


def _empty_state() -> dict:
    return {
        "version": STATE_VERSION,
        "last_updated": None,
        "feeds": {},
        "applied_indicators": [],
        "indicator_to_uuid": {},
    }


def load_state(path: str) -> dict:
    """Load state from JSON file. Returns empty state if the file is missing or corrupt."""
    if not os.path.exists(path):
        logger.info("No state file at %s — starting fresh.", path)
        return _empty_state()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("version") != STATE_VERSION:
            logger.warning(
                "State file version mismatch (got %s, expected %s) — resetting.",
                data.get("version"),
                STATE_VERSION,
            )
            return _empty_state()
        # Ensure required keys exist (forward-compat for older state files)
        for key in ("feeds", "applied_indicators", "indicator_to_uuid"):
            if key not in data:
                data[key] = {} if key != "applied_indicators" else []
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to load state file %s: %s — resetting.", path, exc)
        return _empty_state()


def save_state(state: dict, path: str) -> None:
    """Atomically write state to JSON file."""
    state["last_updated"] = datetime.now(timezone.utc).isoformat()
    state["applied_indicators"] = sorted(state["applied_indicators"])
    tmp_path = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp_path, path)
    except OSError as exc:
        logger.error("Failed to save state file %s: %s", path, exc)
        raise


def compute_delta(
    state: dict, new_indicators: set
) -> tuple[set, set]:
    """Return (to_add, to_remove) sets based on current state vs new indicators."""
    old_set = set(state["applied_indicators"])
    to_add = new_indicators - old_set
    to_remove = old_set - new_indicators
    return to_add, to_remove


def update_state_after_add(state: dict, indicator: str, uuid: str) -> None:
    """Record a successfully added indicator and its UUID."""
    if indicator not in state["applied_indicators"]:
        state["applied_indicators"].append(indicator)
    state["indicator_to_uuid"][indicator] = uuid


def update_state_after_remove(state: dict, indicator: str) -> None:
    """Remove a successfully deleted indicator from state."""
    state["applied_indicators"] = [
        i for i in state["applied_indicators"] if i != indicator
    ]
    state["indicator_to_uuid"].pop(indicator, None)


def record_feed_fetch(state: dict, feed_id: str, indicator_count: int) -> None:
    """Update per-feed metadata after a successful fetch."""
    state["feeds"][feed_id] = {
        "last_fetched": datetime.now(timezone.utc).isoformat(),
        "indicator_count": indicator_count,
    }


def get_feed_last_fetched(state: dict, feed_id: str):
    """Return ISO timestamp string of last successful fetch, or None."""
    return state.get("feeds", {}).get(feed_id, {}).get("last_fetched")
