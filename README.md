# lulu-rules

Automatically updates [LuLu](https://objective-see.org/products/lulu.html) firewall block rules from community-maintained C2 threat intelligence feeds. Runs hourly via a macOS LaunchDaemon and only applies the delta on each run — adding newly identified threats and removing stale ones.

Existing manually-added LuLu rules are never touched. All managed rules use a dedicated key (`com.lulu-rules.c2-feeds`) so they stay isolated.

## Requirements

- macOS 13+
- [LuLu](https://objective-see.org/products/lulu.html) installed
- [lulu-cli](https://github.com/woop/lulu-cli) installed
- Python 3 (ships with macOS)
- Xcode Command Line Tools (for `swiftc`, used to compile the plist helper)

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install lulu-cli
brew install woop/tap/lulu-cli
```

## Install

```bash
sudo bash install.sh
```

This will:
1. Copy the package to `/usr/local/lib/lulu-rules/`
2. Compile the Swift plist helper (`lulu-rules-helper`) with `swiftc -O`
3. Register `/Library/LaunchDaemons/com.lulu-rules.plist`
4. Run the first feed fetch immediately

> **Re-run `install.sh` after any update** to recompile the Swift helper and redeploy the Python package.

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

| Feed | Indicators | Interval |
|------|-----------|----------|
| [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) — abuse.ch | IPv4 | 1h |
| [SSLBL Botnet C2 IPs](https://sslbl.abuse.ch/blacklist/) — abuse.ch | IPv4 | 1h |
| [Bambenek C2 Domains](https://osint.bambenekconsulting.com/feeds/) (high confidence) | Domains | 1h |
| [montysecurity C2-Tracker](https://github.com/montysecurity/C2-Tracker) | IPv4 | 24h |
| [bitwire-it Outbound Blocklist](https://github.com/bitwire-it/ipblocklist) | IPv4, CIDR | 2h |

All feeds are freely available and require no authentication. Feed fetch failures are non-fatal — previously applied indicators for a failed feed are preserved until the next successful fetch.

Supported indicator types: IPv4 addresses, IPv6 addresses, IPv4/IPv6 CIDR ranges, and domain names. Private, loopback, link-local, and reserved ranges are rejected before any rule is applied.

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
validator.py — classify as IPv4, IPv6, CIDR, or domain; discard private/reserved/malformed
    │
    ▼
state.py — compute delta against /var/db/lulu-rules/state.json
    │         to_add    = new threats not yet in LuLu
    │         to_remove = stale threats no longer in any feed
    ▼
plist_writer.py — passes full batch to lulu-rules-helper via JSON on stdin
    │
    ▼
lulu-rules-helper (compiled Swift binary)
    single read of /Library/Objective-See/LuLu/rules.plist
    apply all removes + adds in memory
    single atomic write back to rules.plist
    │
    ▼
lulu-cli reload  (once, immediately after plist write)
    │
    ▼
state.py — save updated state (atomic write)
```

Rule changes are applied in a **single plist read-modify-write** regardless of how many indicators change. `lulu-cli` is used only for the final `reload` call. State is persisted at `/var/db/lulu-rules/state.json` with each indicator's UUID, enabling precise per-rule removal on subsequent runs.

## Runtime paths

| Path | Purpose |
|------|---------|
| `/usr/local/lib/lulu-rules/` | Installed package, config, and compiled Swift helper |
| `/var/db/lulu-rules/state.json` | Persisted indicator state |
| `/var/log/lulu-rules/updater.log` | Rotating log (5 MB × 3) |
| `/Library/LaunchDaemons/com.lulu-rules.plist` | Hourly scheduler |
