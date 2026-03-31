# lulu-rules

Automatically updates [LuLu](https://objective-see.org/products/lulu.html) firewall block rules from community-maintained C2 threat intelligence feeds. Runs hourly via a macOS LaunchDaemon and only applies the delta on each run — adding newly identified threats and removing stale ones.

Existing manually-added LuLu rules are never touched. All managed rules use a dedicated key (`com.lulu-rules.c2-feeds`) so they stay isolated.

## Requirements

- macOS 13+
- [LuLu](https://objective-see.org/products/lulu.html) installed
- [lulu-cli](https://github.com/woop/lulu-cli) installed
- Python 3 (ships with macOS)

Install `lulu-cli` via Homebrew:

```bash
brew install woop/tap/lulu-cli
```

## Install

```bash
sudo bash install.sh
```

This will:
1. Copy the package to `/usr/local/lib/lulu-rules/`
2. Register `/Library/LaunchDaemons/com.lulu-rules.plist`
3. Run the first feed fetch immediately

Monitor the first run:

```bash
tail -f /var/log/lulu-rules/updater.log
```

## Manual update

```bash
sudo bash update.sh
```

Other useful flags:

```bash
sudo bash update.sh --dry-run        # fetch feeds and show delta without changing LuLu
sudo bash update.sh --force-rebuild  # remove all managed rules and re-add from scratch
```

## Uninstall

```bash
sudo bash uninstall.sh
```

Stops the daemon, removes all managed LuLu rules, and deletes the installed files. Log files at `/var/log/lulu-rules/` are retained and must be removed manually if desired.

## Feeds

| Feed | Type | Interval |
|------|------|----------|
| [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) — abuse.ch | IPs | 1h |
| [SSLBL Botnet C2 IPs](https://sslbl.abuse.ch/blacklist/) — abuse.ch | IPs | 1h |
| [Bambenek C2 Domains](https://osint.bambenekconsulting.com/feeds/) (high confidence) | Domains | 1h |
| [montysecurity C2-Tracker](https://github.com/montysecurity/C2-Tracker) | IPs | 24h |
| [bitwire-it Outbound Blocklist](https://github.com/bitwire-it/ipblocklist) | IPs | 2h |

All feeds are freely available and require no authentication. Feed fetch failures are non-fatal — previously applied indicators for a failed feed are preserved until the next successful fetch.

## Adding a feed

Add an entry to `config/feeds.json`:

```json
{
  "id": "my_feed",
  "name": "My Custom Feed",
  "url": "https://example.com/blocklist.txt",
  "type": "ip",
  "parser": "plaintext_comments",
  "enabled": true,
  "update_interval_hours": 24
}
```

Available parsers:

| Parser | Description |
|--------|-------------|
| `plaintext_comments` | One entry per line; lines starting with `#` are ignored |
| `bambenek_csv` | CSV format; extracts the first column (domain) per row |

To support a different format, add a parser function to `lulu_rules/feeds.py` and register it in the `PARSERS` dict.

## How it works

```
config/feeds.json
    │
    ▼
feeds.py — fetch + parse each feed (respecting per-feed intervals)
    │
    ▼
validator.py — discard private IPs, malformed domains
    │
    ▼
state.py — compute delta against /var/db/lulu-rules/state.json
    │         to_add  = new threats not yet in LuLu
    │         to_remove = stale threats no longer in any feed
    ▼
lulu_cli.py
    for each in to_remove: lulu-cli delete --key com.lulu-rules.c2-feeds --uuid UUID
    for each in to_add:    lulu-cli add    --key com.lulu-rules.c2-feeds --addr INDICATOR --action block
    lulu-cli reload (once, after all changes)
    │
    ▼
state.py — save updated state (atomic write)
```

State is persisted at `/var/db/lulu-rules/state.json`. Each indicator is tracked with its lulu-cli UUID so individual rules can be removed precisely without touching anything else.

## Runtime paths

| Path | Purpose |
|------|---------|
| `/usr/local/lib/lulu-rules/` | Installed package and config |
| `/var/db/lulu-rules/state.json` | Persisted indicator state |
| `/var/log/lulu-rules/updater.log` | Rotating log (5 MB × 3) |
| `/Library/LaunchDaemons/com.lulu-rules.plist` | Hourly scheduler |
