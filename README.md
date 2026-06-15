<p align="center">
  <h1 align="center">🛡️ IOC Triage</h1>
  <p align="center">
    <strong>A terminal-based TUI for parsing and triaging Indicators of Compromise (IOCs).</strong>
  </p>
  <p align="center">
    Parse, triage, analyze, tag, and export Indicators of Compromise — directly from your terminal.
  </p>
  <p align="center">
    <a href="#features"><img src="https://img.shields.io/badge/IOC_Types-10+-blue?style=flat-square" alt="IOC Types"></a>
    <a href="#features"><img src="https://img.shields.io/badge/Platforms-30+-green?style=flat-square" alt="Lookup Platforms"></a>
    <a href="#export"><img src="https://img.shields.io/badge/Export-JSON_%7C_CSV-orange?style=flat-square" alt="Export Formats"></a>
    <img src="https://img.shields.io/badge/Language-Rust-red?style=flat-square&logo=rust" alt="Rust">
    <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License">
  </p>
</p>

---

## 🔍 What is IOC Triage?

**IOC Triage** is a terminal-based (TUI) tool built in Rust for **Cyber Threat Intelligence (CTI) analysts**, **SOC operators**, and **OSINT investigators** who need to quickly process and triage large batches of Indicators of Compromise.

Paste a blob of raw text — IOC Triage automatically detects, classifies, deduplicates, and presents every indicator in an interactive dashboard with one-click lookups to 30+ threat intelligence platforms.

## ✨ Features

### 🎯 Automatic IOC Detection
Paste raw text in any format and IOC Triage instantly identifies:

| Type | Example / Format | Priority |
|------|------------------|----------|
| **IPv4** | `192.168.1.1` | Medium |
| **IPv6** | `2001:0db8:85a3::8a2e:0370:7334` | Medium |
| **Domain** | `evil-domain.com` | Medium |
| **URL** | `https://malware.example.com/payload` | Medium |
| **MD5** | `d41d8cd98f00b204e9800998ecf8427e` | High |
| **SHA1** | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | High |
| **SHA256** | `e3b0c44298fc1c149afbf4c8...` | High |
| **Email** | `attacker@evil.com` | Low |
| **CVE** | `CVE-2024-12345` | High |
| **Crypto Wallet** | `bc1q...` (SegWit), `0x...` (ETH), `4...` (XMR), `L...` (LTC), `D...` (DOGE) | Medium |

### 🔓 Defanging Support
Automatically normalizes common defanged formats:
- `hxxp://` / `hXXp://` → `http://`
- `hxxps://` / `hXXps://` → `https://`
- `[.]` / `(.)` / `[dot]` → `.`
- `[:]` → `:`
- `[@]` / `[at]` → `@`

### 🌐 One-Click Threat Intel Lookups
Every detected IOC gets mapped to relevant lookup URLs across **35+ platforms**:

| Platform | IOC Types | Description / Formats |
|----------|-----------|-----------------------|
| **VirusTotal** | IPs, Domains, URLs, Hashes | URL-safe base64-encoded URL checks, file hash checks |
| **AbuseIPDB** | IPs | IP reputation and abuse reporting history |
| **Shodan** | IPs | Host information, open ports, and banners |
| **GreyNoise** | IPs | Noise vs targeted attack scanner |
| **IPinfo** | IPs | IP geolocation and ASN mapping |
| **Cisco Talos** | IPs, Domains | Global intelligence and web reputation network |
| **URLScan.io** | Domains, URLs | Interactive web crawls (Lucene-quoted queries) |
| **DomainTools** | Domains | WHOIS and hosting records |
| **Wayback Machine** | Domains, URLs | Historical page contents (`/*` recursive crawls for domains) |
| **CRT.sh** | Domains | SSL/TLS certificates and subdomain discovery |
| **MalwareBazaar** | Hashes | Direct sample sample/browse (SHA256, SHA1, MD5) |
| **Hybrid Analysis** | Hashes | Automated malware analysis sandbox search |
| **ANY.RUN** | Hashes | Public task submissions database text search |
| **AlienVault OTX** | Hashes | Open Threat Exchange indicator details |
| **NVD** | CVEs | National Vulnerability Database vulnerability details |
| **MITRE CVE** | CVEs | Official CVE Dictionary reference entries |
| **CVE Details** | CVEs | Consolidated vulnerability history (trailing slash formatted) |
| **MITRE ATT&CK** | CVEs | Adversary tactics, techniques, and procedures mapping |
| **HaveIBeenPwned** | Emails | Email data breach account checks |
| **Epieos** | Emails | Reverse email search and osint profiling |
| **IntelX** | Emails | Intelligence X data leak searches |
| **Etherscan** | Crypto | Ethereum block explorer |
| **XMRChain** | Crypto | Monero block explorer (XMR privacy check) |
| **Blockchain.com** | Crypto | Bitcoin block explorer |
| **Blockchair** | Crypto | Universal multi-coin explorer (BTC, ETH, LTC, DOGE) |

Press `O` to open all URLs for an IOC, or `1-9` to open a specific one.

### 🏷️ Tagging & Notes
- **Tag indicators**: Cycle through `Clean → Suspicious → Malicious → False Positive` with `T`
- **Add notes**: Press `N` to attach analyst notes to any indicator
- **Track changes**: Unsaved changes are tracked throughout the session

### 📤 Export
Export your triaged session in two formats:
- **JSON** — Full session metadata envelope with all indicator data
- **CSV** — Flat table format for spreadsheets and SIEMs

Files are timestamped: `ioc_triage_YYYYMMDD_HHMMSS.json`

---

## 🚀 Installation

### Build from source

#### Prerequisites
- [Rust](https://rustup.rs/) (1.70+ recommended)

```bash
git clone https://github.com/KennethHelmuth/Ioc-Triage-tool.git
cd Ioc-Triage-tool
cargo build --release
```

The binary will be at `target/release/ioc-triage`.

### Run Directly

```bash
cargo run
```

---

## 📖 Usage

### Quick Start

1. **Launch**:
   - **Interactive**: `cargo run` (presents paste modal)
   - **File Argument**: `cargo run -- suspicious.txt` (or `./target/release/ioc-triage suspicious.txt`)
   - **Piped Stdin**: `cat logs.txt | cargo run`
2. **Triage**: Navigate, multi-select, tag, add notes, search, filter, and open lookups
3. **Export**: Press `E` to export your session

### Keybindings

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Cycle active view tab forward / backward |
| `F1` / `F2` / `F3` / `F4` | Switch view directly (Dashboard / Grid / Lookups / Settings) |
| `↑` / `↓` | Navigate rows / settings / platforms |
| `PgUp` / `PgDn` | Jump 10 rows |
| `Home` / `End` | Jump to first/last row |
| `Space` | Toggle checkbox (indicator selection or lookup platforms) |
| `A` / `U` | Select all / Unselect all (filtered rows or lookup platforms) |
| `:` | Open Vim-style command palette (execute `:help`, `:clear`, `:tag`, `:filter`, `:sort`, `:limit`, `:dir`) |
| `/` | Enter search query mode (filters by value/notes) |
| `F` / `Shift+F` | Cycle tag filter forward / backward |
| `Y` | Open interactive type filter modal |
| `S` | Open interactive sorting modal |
| `x` | Reset/Clear all active search and filters |
| `I` | Paste new IOCs (adds to session) |
| `O` | Open all lookup URLs in browser (supports bulk) |
| `1-9` | Open specific lookup URL by number |
| `T` / `Shift+T` | Cycle tag forward / backward (supports bulk) |
| `N` | Edit note for selected indicator |
| `E` | Export session (JSON or CSV) |
| `C` | Copy indicator value to clipboard (supports bulk) |
| `D` | Delete selected indicator (supports bulk) |
| `?` | Show help overlay |
| `Q` / `Ctrl+C` | Quit |

---

## ⚙️ Configuration

Configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `EXPORT_DIR` | Current directory | Directory for exported files |
| `MAX_IOC_LIMIT` | `10000` | Maximum IOCs per session |

```bash
EXPORT_DIR=./exports MAX_IOC_LIMIT=5000 cargo run
```

---

## 🏗️ Architecture

```
ioc-triage/
├── Cargo.toml
└── src/
    ├── main.rs        # Entry point, terminal setup, event loop
    ├── models.rs      # Core data structures (IocEntry, AppState, enums)
    ├── config.rs      # Environment-based configuration
    ├── parser.rs      # Regex-based IOC detection with unit tests
    ├── lookup.rs      # Threat intel URL generation (30+ platforms)
    ├── tui.rs         # Full ratatui TUI (table, panels, modals, keybindings)
    └── export.rs      # JSON & CSV export with session metadata
```

### Design Principles

- **Zero panics** — All errors handled gracefully with `anyhow`
- **Zero `.unwrap()`** in non-test code paths
- **Compiled regex** — All patterns compiled once via `lazy_static!`
- **Unicode-safe** — String truncation uses `.chars()`, not byte slicing
- **Clean exit** — Terminal always restored, even on panic

---

## 🧪 Testing

```bash
cargo test
```

The test suite includes **20 comprehensive unit tests** covering:
- Threat intel lookup URL generation & Base64 encoder
- Each IOC type detection (including Legacy, SegWit/Taproot BTC, ETH, XMR, LTC, DOGE, XRP)
- Defanged input normalization
- Mixed delimiter handling
- Duplicate detection and counting
- Priority auto-assignment
- Edge cases (empty input, etc.)

---

## 📦 Dependencies

| Crate | Purpose |
|-------|---------|
| `ratatui` | Terminal UI framework |
| `crossterm` | Terminal backend & event handling |
| `regex` | IOC pattern matching |
| `lazy_static` | One-time regex compilation |
| `serde` / `serde_json` | JSON serialization |
| `csv` | CSV export |
| `chrono` | Timestamps |
| `arboard` | Clipboard access |
| `open` | Open URLs in default browser |
| `anyhow` | Error handling |

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

## ⚠️ Status

Stable Release (v1.0.0).

Fully revamped workspace with production-grade TUI responsiveness, robust styling, and comprehensive OSINT integration.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with 🦀 Rust for the CTI community
</p>
