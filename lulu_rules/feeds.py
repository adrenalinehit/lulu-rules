"""Feed fetching and parsing for community C2 threat intel sources."""

import csv
import io
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from typing import Callable

from .state import get_feed_last_fetched, record_feed_fetch
from .validator import classify_indicator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_plaintext_comments(content: str) -> list[str]:
    """Parse a plain-text list that uses '#' for comment lines."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Some feeds include port numbers (e.g. "1.2.3.4:447") — strip port
        if ':' in line and not line.startswith('#'):
            line = line.split(':')[0].strip()
        results.append(line)
    return results


def parse_bambenek_csv(content: str) -> list[str]:
    """Parse Bambenek feed: CSV where column 0 is the domain."""
    results = []
    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row:
            continue
        first = row[0].strip()
        if not first or first.startswith('#'):
            continue
        results.append(first)
    return results


PARSERS: dict[str, Callable[[str], list[str]]] = {
    "plaintext_comments": parse_plaintext_comments,
    "bambenek_csv": parse_bambenek_csv,
}


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def fetch_feed(feed_config: dict, timeout: int = 30) -> str | None:
    """Download a feed URL and return its content as a string, or None on failure."""
    url = feed_config["url"]
    headers = feed_config.get("http_headers", {})
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        logger.warning("HTTP %s fetching feed '%s' (%s)", exc.code, feed_config["id"], url)
    except urllib.error.URLError as exc:
        logger.warning("Network error fetching feed '%s': %s", feed_config["id"], exc.reason)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unexpected error fetching feed '%s': %s", feed_config["id"], exc)
    return None


# ---------------------------------------------------------------------------
# Per-feed interval throttling
# ---------------------------------------------------------------------------

def _should_fetch(feed_config: dict, state: dict) -> bool:
    """Return True if enough time has passed since the last successful fetch."""
    last_fetched_str = get_feed_last_fetched(state, feed_config["id"])
    if last_fetched_str is None:
        return True
    try:
        last_fetched = datetime.fromisoformat(last_fetched_str)
    except ValueError:
        return True
    interval = timedelta(hours=feed_config.get("update_interval_hours", 1))
    return datetime.now(timezone.utc) >= last_fetched + interval


def _get_cached_indicators(feed_id: str, state: dict) -> set[str]:
    """Return the set of indicators that were last applied from this feed."""
    # We don't store per-feed indicator lists, so we can't reconstruct them.
    # The delta approach handles this correctly: if we skip a fetch, the
    # previously applied indicators remain in state["applied_indicators"].
    # Returning an empty set here would cause them to be removed — wrong.
    # Instead, callers must treat a skipped feed as "no change" by not
    # contributing its indicators to the removal set.
    return set()


# ---------------------------------------------------------------------------
# Main collection entry point
# ---------------------------------------------------------------------------

def collect_all_indicators(feeds_config: list[dict], state: dict) -> dict[str, set]:
    """
    Fetch and parse all enabled feeds, respecting per-feed throttle intervals.

    Returns {"ip": set[str], "domain": set[str], "skipped_feed_ids": set[str]}.
    "skipped_feed_ids" contains feeds that were not re-fetched (interval not elapsed
    or fetch failed) — their existing indicators in state must be preserved.
    """
    ip_set: set[str] = set()
    domain_set: set[str] = set()
    # Track which feeds we successfully fetched new data for
    fetched_feed_ids: set[str] = set()
    skipped_feed_ids: set[str] = set()

    for feed in feeds_config:
        if not feed.get("enabled", True):
            logger.debug("Feed '%s' is disabled — skipping.", feed["id"])
            skipped_feed_ids.add(feed["id"])
            continue

        if not _should_fetch(feed, state):
            logger.debug(
                "Feed '%s' interval not elapsed — using cached indicators.", feed["id"]
            )
            skipped_feed_ids.add(feed["id"])
            continue

        logger.info("Fetching feed '%s' from %s", feed["id"], feed["url"])
        content = fetch_feed(feed)
        if content is None:
            logger.warning(
                "Feed '%s' fetch failed — preserving previously applied indicators.",
                feed["id"],
            )
            skipped_feed_ids.add(feed["id"])
            continue

        parser_name = feed.get("parser", "plaintext_comments")
        parser = PARSERS.get(parser_name)
        if parser is None:
            logger.error("Unknown parser '%s' for feed '%s'.", parser_name, feed["id"])
            skipped_feed_ids.add(feed["id"])
            continue

        raw_values = parser(content)
        valid_count = 0
        for raw in raw_values:
            kind = classify_indicator(raw)
            if kind == "ip":
                ip_set.add(raw)
                valid_count += 1
            elif kind == "domain":
                domain_set.add(raw)
                valid_count += 1
            else:
                logger.debug("Feed '%s': discarding invalid indicator %r", feed["id"], raw)

        logger.info(
            "Feed '%s': %d valid indicators (%d raw lines).",
            feed["id"],
            valid_count,
            len(raw_values),
        )
        record_feed_fetch(state, feed["id"], valid_count)
        fetched_feed_ids.add(feed["id"])

    total = len(ip_set) + len(domain_set)
    logger.info(
        "Collected %d unique indicators total (%d IPs, %d domains) from %d/%d feeds.",
        total,
        len(ip_set),
        len(domain_set),
        len(fetched_feed_ids),
        len(feeds_config),
    )
    return {"ip": ip_set, "domain": domain_set, "skipped_feed_ids": skipped_feed_ids}
