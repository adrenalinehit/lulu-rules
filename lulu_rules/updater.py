"""
Main orchestrator for lulu-rules.

Usage:
    sudo python3 -m lulu_rules.updater [--dry-run] [--force-rebuild] [--config PATH]

Options:
    --dry-run        Fetch feeds and compute delta but do not modify LuLu rules.
    --force-rebuild  Remove all managed rules and re-add the full current feed set.
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

    # Always log to stderr so manual runs are visible in the terminal
    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.DEBUG if dry_run else logging.INFO)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    # When running as a daemon, also write to the rotating log file
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
    parser.add_argument("--force-rebuild", action="store_true", help="Remove and re-add all managed rules.")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to feeds.json.")
    args = parser.parse_args()

    _setup_logging(args.dry_run)
    logger = logging.getLogger("updater")

    # Require root for any non-dry-run operation
    if not args.dry_run and os.geteuid() != 0:
        logger.critical("This script must be run as root (use sudo).")
        sys.exit(1)

    # Import here so logging is configured first
    from .feeds import collect_all_indicators
    from .lulu_cli import (
        add_rule,
        find_lulu_cli,
        is_lulu_running,
        reload_lulu,
        remove_all_managed_rules,
        remove_rule,
    )
    from .state import (
        compute_delta,
        load_state,
        save_state,
        update_state_after_add,
        update_state_after_remove,
    )

    # Locate lulu-cli
    lulu_cli_path = find_lulu_cli()
    if lulu_cli_path is None:
        logger.critical(
            "lulu-cli not found. Install it with:\n"
            "  brew install woop/tap/lulu-cli\n"
            "Or from source: https://github.com/woop/lulu-cli"
        )
        sys.exit(1)
    logger.info("Using lulu-cli at %s", lulu_cli_path)

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

    # Build the full desired indicator set.
    # For feeds that were skipped (throttled or failed), preserve their previously
    # applied indicators so they are not removed.
    new_indicators = ip_set | cidr_set | domain_set

    # Identify which indicators belong to skipped feeds by checking state.
    # We don't store per-feed indicator lists, so we approximate: any indicator
    # currently in state that was NOT returned by a successfully fetched feed
    # should be preserved if its feed was skipped.
    #
    # Simpler correct approach: augment new_indicators with all currently-applied
    # indicators that we don't know the feed origin of (i.e. all of applied_indicators
    # minus those that a fetched feed could have returned).
    #
    # Since we can't attribute individual state indicators to feeds without additional
    # tracking, the safe default is: preserve all existing state indicators when any
    # feed was skipped. This means we only remove indicators that were in state AND
    # were NOT returned by ANY successfully fetched feed AND no feeds were skipped.
    if skipped_feed_ids:
        existing = set(state["applied_indicators"])
        # Add back existing indicators that new fetches didn't explicitly cover,
        # so they are not considered for removal.
        new_indicators = new_indicators | (existing - new_indicators)
        logger.debug(
            "%d feed(s) skipped — preserving all existing indicators to avoid stale removals.",
            len(skipped_feed_ids),
        )

    # Compute delta
    if args.force_rebuild:
        to_add = new_indicators
        to_remove: set = set()
        logger.info("--force-rebuild: will remove all managed rules and re-add %d indicators.", len(to_add))
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

    changes_made = False

    # Force rebuild: remove everything first
    if args.force_rebuild:
        if remove_all_managed_rules(lulu_cli_path):
            state["applied_indicators"] = []
            state["indicator_to_uuid"] = {}
        else:
            logger.error("Force rebuild failed at removal step — aborting to avoid inconsistent state.")
            sys.exit(1)

    # Remove stale rules
    remove_errors = 0
    for indicator in sorted(to_remove):
        uuid = state["indicator_to_uuid"].get(indicator)
        if uuid:
            if remove_rule(uuid, lulu_cli_path):
                update_state_after_remove(state, indicator)
                changes_made = True
            else:
                remove_errors += 1
        else:
            # No UUID recorded — remove from state tracking only
            logger.warning("No UUID for indicator %r — removing from state without lulu-cli call.", indicator)
            update_state_after_remove(state, indicator)

    if remove_errors:
        logger.warning("%d rule removal(s) failed — will retry on next run.", remove_errors)

    # Add new rules
    add_errors = 0
    for indicator in sorted(to_add):
        uuid = add_rule(indicator, lulu_cli_path)
        if uuid:
            update_state_after_add(state, indicator, uuid)
            changes_made = True
        else:
            add_errors += 1

    if add_errors:
        logger.warning(
            "%d rule addition(s) failed — will retry on next run.", add_errors
        )

    # Save state atomically
    save_state(state, STATE_PATH)

    total_active = len(state["applied_indicators"])
    logger.info(
        "Updated LuLu: added %d, removed %d, %d total active managed rules.",
        len(to_add) - add_errors,
        len(to_remove) - remove_errors,
        total_active,
    )

    # Reload LuLu if anything changed
    if changes_made and lulu_running:
        reload_lulu(lulu_cli_path)
    elif changes_made and not lulu_running:
        logger.info("Changes staged. LuLu will pick them up when it next starts.")
    else:
        logger.info("No changes — LuLu reload skipped.")


if __name__ == "__main__":
    main()
