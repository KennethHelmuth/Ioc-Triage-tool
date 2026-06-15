# Changelog

All notable changes to IOC Triage will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2026-06-15

### Added
- **Multi-wallet Cryptocurrency Parser**: Automatic detection and extraction of Bitcoin (Legacy, Nested SegWit, Native SegWit, Taproot), Ethereum, Monero, Litecoin, Dogecoin, and Ripple wallet addresses.
- **Theme-Agnostic TUI Visuals**: Standardized high-contrast ANSI Cyan active tab rendering, transparent inactive tabs, and explicit 256-color grayscales (`Indexed(236)` for backgrounds/prompt, `Indexed(238)` for selection highlights) to guarantee uniform styling across custom terminal themes.
- **Audited & Restructured OSINT Lookups**: Corrected VirusTotal base64-urlsafe URL formatting, urlscan.io double-quoted domain/URL queries, and exploit-db lookups (now routing to the official MITRE CVE dictionary). Added Cisco Talos, CRT.sh, IntelX, OTX, and trailing-slash CVE Details links.
- **Piped Stdin & CLI Argument Support**: Load indicators directly from pipelines (e.g. `cat logs.txt | ioc-triage`) or files (e.g. `ioc-triage suspicious.txt`).
- **Workspace Navigation & Commands**: Multi-view tabs (`F1 - F4`), Vim-style command palette (`:`), and persistent live activity logging.
- **Interactive Triage Grid**: Text-search query filter (`/`), multi-select checklist rows (`Space`, `A`, `U`), dynamic sorting, tag cycling, note editing, and bulk actions.
- **Robust Sizing Safety**: Pauses rendering and prompts for resize if terminal window size is too small (`< 60x12`).
- **Unit Tests**: 20 comprehensive unit tests validating parsing, lookup URL generation, filtering, sorting, and bulk action logic.

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
