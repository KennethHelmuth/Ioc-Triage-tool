# Changelog

All notable changes to IOC Triage will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-04-27

### Added
- Full interactive TUI built with ratatui and crossterm
- Automatic detection of 10 IOC types: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, CVE, Bitcoin
- Defanging normalization for hxxp, [.], (.), [dot], [@], [at]
- Deduplication with input vs unique count tracking
- Priority auto-assignment per IOC type
- 30+ threat intel platform lookup URLs per IOC
- Interactive tagging: Clean, Suspicious, Malicious, False Positive
- Inline note editing per indicator
- JSON and CSV export with timestamped filenames
- Clipboard copy support via arboard
- One-key URL opening in default browser
- 15 unit tests for parser module
- Environment-based configuration via EXPORT_DIR and MAX_IOC_LIMIT
- Panic-safe terminal cleanup on exit
