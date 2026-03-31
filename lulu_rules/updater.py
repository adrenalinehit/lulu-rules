"""
Main orchestrator for lulu-rules.

Usage:
    sudo python3 -m lulu_rules.updater [--dry-run] [--force-rebuild] [--config PATH]

Options:
    --dry-run        Fetch feeds and compute delta but do not modify LuLu rules.
    --force-rebuild  Wipe all managed rules and re-add the full current feed set.
    --config PATH    Path to feeds.json (default: config/feeds.json relative to CWD).
"""

import argparse
import json
import logging
import logging.handlers
import os
import sys

LOG_PATH = "/var/log/lulu-rules/updater.log"
STATE_PATH = "/var/db/lulu-rules/state.json"
DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), "..", "config", "feeds.json")


def _setup_logging(dry_run: bool) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")

    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.DEBUG if dry_run else logging.INFO)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    if not dry_run:
        try:
            os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3
            )
            fh.setLevel(logging.INFO)
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError as exc:
            logging.warning("Could not open log file %s: %s", LOG_PATH, exc)


def _load_config(path: str) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data["feeds"]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        logging.critical("Failed to load feeds config from %s: %s", path, exc)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Update LuLu firewall C2 block rules.")
    parser.add_argument("--dry-run", action="store_true", help="Compute delta without modifying LuLu.")
    parser.add_argument("--force-rebuild", action="store_true", help="Wipe and re-add all managed rules.")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to feeds.json.")
    args = parser.parse_args()

    _setup_logging(args.dry_run)
    logger = logging.getLogger("updater")

    if not args.dry_run and os.geteuid() != 0:
        logger.critical("This script must be run as root (use sudo).")
        sys.exit(1)

    from .feeds import collect_all_indicators
    from .lulu_cli import find_lulu_cli, is_lulu_running, reload_lulu
    from .plist_writer import batch_apply, find_helper
    from .state import (
        compute_delta,
        load_state,
        save_state,
        update_state_after_add,
        update_state_after_remove,
    )

    # Verify the Swift helper is available
    if not args.dry_run and find_helper() is None:
        logger.critical(
            "lulu-rules-helper not found. Run install.sh to compile it.\n"
            "Requires Xcode Command Line Tools: xcode-select --install"
        )
        sys.exit(1)

    # lulu-cli is only needed for reload
    lulu_cli_path = find_lulu_cli()
    if lulu_cli_path is None:
        logger.critical(
            "lulu-cli not found. Install it with:\n"
            "  brew install woop/tap/lulu-cli"
        )
        sys.exit(1)
    logger.info("Using lulu-cli at %s (for reload only)", lulu_cli_path)

    feeds_config = _load_config(args.config)
    state = load_state(STATE_PATH)

    lulu_running = is_lulu_running()
    if not lulu_running:
        logger.warning("LuLu does not appear to be running. Rules will be staged but not reloaded.")

    # Fetch and parse all feeds
    result = collect_all_indicators(feeds_config, state)
    ip_set: set = result["ip"]
    cidr_set: set = result["cidr"]
    domain_set: set = result["domain"]
    skipped_feed_ids: set = result["skipped_feed_ids"]

    new_indicators = ip_set | cidr_set | domain_set

    # Preserve indicators from skipped/failed feeds so they aren't removed
    if skipped_feed_ids:
        existing = set(state["applied_indicators"])
        new_indicators = new_indicators | existing
        logger.debug(
            "%d feed(s) skipped — preserving existing indicators to avoid stale removals.",
            len(skipped_feed_ids),
        )

    # Compute delta
    if args.force_rebuild:
        to_add = new_indicators
        to_remove: set = set()
        logger.info("--force-rebuild: wiping managed rules and re-adding %d indicators.", len(to_add))
    else:
        to_add, to_remove = compute_delta(state, new_indicators)

    logger.info(
        "Delta: %d to add, %d to remove, %d unchanged.",
        len(to_add),
        len(to_remove),
        len(state["applied_indicators"]) - len(to_remove),
    )

    if args.dry_run:
        logger.info("[DRY RUN] No changes made to LuLu.")
        if to_add:
            logger.info("[DRY RUN] Would add: %s%s",
                        ", ".join(sorted(to_add)[:10]),
                        " ..." if len(to_add) > 10 else "")
        if to_remove:
            logger.info("[DRY RUN] Would remove: %s%s",
                        ", ".join(sorted(to_remove)[:10]),
                        " ..." if len(to_remove) > 10 else "")
        return

    if not to_add and not to_remove and not args.force_rebuild:
        logger.info("No changes — LuLu reload skipped.")
        save_state(state, STATE_PATH)
        return

    # Collect UUIDs of rules to remove
    to_remove_uuids = {
        state["indicator_to_uuid"][i]
        for i in to_remove
        if i in state["indicator_to_uuid"]
    }

    # Single plist read-modify-write for the entire batch
    added_uuids = batch_apply(
        to_add=to_add,
        to_remove_uuids=to_remove_uuids,
        clear_managed=args.force_rebuild,
    )

    # Update state to match what was written
    if args.force_rebuild:
        state["applied_indicators"] = []
        state["indicator_to_uuid"] = {}

    for indicator in to_remove:
        update_state_after_remove(state, indicator)

    for indicator, rule_uuid in added_uuids.items():
        update_state_after_add(state, indicator, rule_uuid)

    save_state(state, STATE_PATH)

    logger.info(
        "Updated LuLu: added %d, removed %d, %d total active managed rules.",
        len(added_uuids),
        len(to_remove),
        len(state["applied_indicators"]),
    )

    if lulu_running:
        reload_lulu(lulu_cli_path)
    else:
        logger.info("Changes staged. LuLu will pick them up when it next starts.")


if __name__ == "__main__":
    main()
