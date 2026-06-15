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

| Type | Example | Priority |
|------|---------|----------|
| **IPv4** | `192.168.1.1` | Medium |
| **IPv6** | `2001:0db8:85a3::8a2e:0370:7334` | Medium |
| **Domain** | `evil-domain.com` | Medium |
| **URL** | `https://malware.example.com/payload` | Medium |
| **MD5** | `d41d8cd98f00b204e9800998ecf8427e` | High |
| **SHA1** | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | High |
| **SHA256** | `e3b0c44298fc1c149afbf4c8...` | High |
| **Email** | `attacker@evil.com` | Low |
| **CVE** | `CVE-2024-12345` | High |
| **Bitcoin Wallet** | `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` | Medium |

### 🔓 Defanging Support
Automatically normalizes common defanged formats:
- `hxxp://` → `http://`
- `hxxps://` → `https://`
- `[.]` / `(.)` / `[dot]` → `.`
- `[:]` → `:`
- `[@]` / `[at]` → `@`

### 🌐 One-Click Threat Intel Lookups
Every detected IOC gets mapped to relevant lookup URLs across **30+ platforms**:

| Platform | IOC Types |
|----------|-----------|
| **VirusTotal** | IPs, Domains, URLs, Hashes |
| **AbuseIPDB** | IPs |
| **Shodan** | IPs |
| **GreyNoise** | IPs |
| **IPinfo** | IPs |
| **URLScan.io** | Domains, URLs |
| **DomainTools** | Domains |
| **Wayback Machine** | Domains |
| **MalwareBazaar** | Hashes |
| **Hybrid Analysis** | Hashes |
| **ANY.RUN** | Hashes |
| **NVD** | CVEs |
| **Exploit-DB** | CVEs |
| **MITRE ATT&CK** | CVEs |
| **CVE Details** | CVEs |
| **HaveIBeenPwned** | Emails |
| **Blockchain.com** | Bitcoin |
| **Blockchair** | Bitcoin |

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

1. **Launch**: `cargo run` (or `./target/release/ioc-triage`)
2. **Paste IOCs**: The paste modal opens automatically — paste your raw IOC text
3. **Confirm**: Press `Enter` twice to parse
4. **Triage**: Navigate, tag, add notes, and open lookups
5. **Export**: Press `E` to export your session

### Keybindings

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate rows |
| `PgUp` / `PgDn` | Jump 10 rows |
| `Home` / `End` | Jump to first/last row |
| `I` | Paste new IOCs |
| `O` | Open all lookup URLs in browser |
| `1-9` | Open specific lookup URL by number |
| `T` | Cycle tag forward |
| `Shift+T` | Cycle tag backward |
| `N` | Edit note for selected indicator |
| `E` | Export session (JSON or CSV) |
| `C` | Copy indicator value to clipboard |
| `D` | Delete selected indicator |
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
    ├── parser.rs      # Regex-based IOC detection with 15 unit tests
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

The parser module includes **15 unit tests** covering:
- Each IOC type detection
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

Early release (v0.1.0).

Core features are implemented and tested, but edge cases and UX will continue to improve.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with 🦀 Rust for the CTI community
</p>
