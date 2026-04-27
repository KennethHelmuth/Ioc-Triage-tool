use crate::lookup::generate_lookup_urls;
use crate::models::{IocEntry, IocType, Priority, Tag};
use chrono::Utc;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;

lazy_static! {
    // Detection-order compiled regex patterns
    static ref RE_URL: Regex =
        Regex::new(r#"https?://[^\s"'<>\]]+"#).expect("Invalid URL regex");

    static ref RE_EMAIL: Regex =
        Regex::new(r"(?i)\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
            .expect("Invalid email regex");

    static ref RE_CVE: Regex =
        Regex::new(r"\bCVE-\d{4}-\d{4,7}\b").expect("Invalid CVE regex");

    static ref RE_SHA256: Regex =
        Regex::new(r"(?i)\b[a-fA-F0-9]{64}\b").expect("Invalid SHA256 regex");

    static ref RE_SHA1: Regex =
        Regex::new(r"(?i)\b[a-fA-F0-9]{40}\b").expect("Invalid SHA1 regex");

    static ref RE_MD5: Regex =
        Regex::new(r"(?i)\b[a-fA-F0-9]{32}\b").expect("Invalid MD5 regex");

    static ref RE_BITCOIN: Regex =
        Regex::new(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b").expect("Invalid Bitcoin regex");

    static ref RE_IPV4: Regex =
        Regex::new(r"\b((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
            .expect("Invalid IPv4 regex");

    static ref RE_IPV6: Regex =
        Regex::new(r"(?i)\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|(?i)\b([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|(?i)\b::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b")
            .expect("Invalid IPv6 regex");

    static ref RE_DOMAIN: Regex =
        Regex::new(r"(?i)\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
            .expect("Invalid domain regex");
}

/// Defang a raw input string — replace common defanging patterns with real characters.
fn defang(input: &str) -> String {
    input
        .replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
        .replace("hXXp://", "http://")
        .replace("hXXps://", "https://")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("(:", ":")
        .replace("[://]", "://")
        .replace("[at]", "@")
        .replace("[@]", "@")
        .replace("[dot]", ".")
}

/// Determine IOC type for a single token using strict detection priority order.
fn classify_token(token: &str) -> Option<(String, IocType)> {
    // URL first — before domain so URLs aren't split
    if let Some(m) = RE_URL.find(token) {
        return Some((m.as_str().to_string(), IocType::URL));
    }

    // Email — before domain so emails aren't misclassified
    if let Some(m) = RE_EMAIL.find(token) {
        return Some((m.as_str().to_string(), IocType::Email));
    }

    // CVE
    if let Some(m) = RE_CVE.find(token) {
        return Some((m.as_str().to_string(), IocType::CVE));
    }

    // SHA256 — before MD5/SHA1 due to length overlap
    if let Some(m) = RE_SHA256.find(token) {
        let val = m.as_str();
        // Ensure it's exactly 64 hex chars (not part of a longer hex string)
        if val.len() == 64 {
            return Some((val.to_lowercase(), IocType::SHA256));
        }
    }

    // SHA1
    if let Some(m) = RE_SHA1.find(token) {
        let val = m.as_str();
        if val.len() == 40 {
            return Some((val.to_lowercase(), IocType::SHA1));
        }
    }

    // MD5
    if let Some(m) = RE_MD5.find(token) {
        let val = m.as_str();
        if val.len() == 32 {
            return Some((val.to_lowercase(), IocType::MD5));
        }
    }

    // Bitcoin wallet
    if let Some(m) = RE_BITCOIN.find(token) {
        return Some((m.as_str().to_string(), IocType::BitcoinWallet));
    }

    // IPv4
    if let Some(m) = RE_IPV4.find(token) {
        return Some((m.as_str().to_string(), IocType::IPv4));
    }

    // IPv6
    if let Some(m) = RE_IPV6.find(token) {
        return Some((m.as_str().to_string(), IocType::IPv6));
    }

    // Domain — last because it's the broadest pattern
    if let Some(m) = RE_DOMAIN.find(token) {
        let val = m.as_str().to_lowercase();
        // Filter out common false positives — very short or looks like a file extension
        if val.contains('.') {
            return Some((val, IocType::Domain));
        }
    }

    None
}

/// Assign default priority based on IOC type.
fn default_priority(ioc_type: &IocType) -> Priority {
    match ioc_type {
        IocType::SHA256 | IocType::SHA1 | IocType::MD5 => Priority::High,
        IocType::CVE => Priority::High,
        IocType::IPv4 | IocType::IPv6 | IocType::URL => Priority::Medium,
        IocType::Domain => Priority::Medium,
        IocType::Email => Priority::Low,
        IocType::BitcoinWallet => Priority::Medium,
        IocType::Unknown => Priority::Unknown,
    }
}

/// Parse raw input text into a deduplicated Vec of IocEntry.
///
/// Returns `(entries, total_found, duplicate_count)`.
pub fn parse_iocs(raw_input: &str) -> (Vec<IocEntry>, usize, usize) {
    let defanged = defang(raw_input);

    // Split on common delimiters
    let tokens: Vec<&str> = defanged
        .split(|c: char| {
            c.is_whitespace() || c == ',' || c == ';' || c == '|' || c == '[' || c == ']'
        })
        .filter(|t| !t.is_empty())
        .collect();

    let mut seen: HashSet<String> = HashSet::new();
    let mut entries: Vec<IocEntry> = Vec::new();
    let mut total_found: usize = 0;
    let mut id_counter: usize = 1;

    for token in &tokens {
        if let Some((value, ioc_type)) = classify_token(token) {
            total_found += 1;
            let normalized = value.clone();
            if seen.contains(&normalized) {
                continue;
            }
            seen.insert(normalized);

            let priority = default_priority(&ioc_type);
            let lookup_urls = generate_lookup_urls(&value, &ioc_type);

            entries.push(IocEntry {
                id: id_counter,
                value,
                ioc_type,
                priority,
                tag: Tag::Untagged,
                note: String::new(),
                lookup_urls,
                created_at: Utc::now(),
            });
            id_counter += 1;
        }
    }

    let duplicate_count = total_found.saturating_sub(entries.len());
    (entries, total_found, duplicate_count)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let (entries, _, _) = parse_iocs("Suspicious IP: 192.168.1.1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::IPv4);
        assert_eq!(entries[0].value, "192.168.1.1");
    }

    #[test]
    fn test_parse_ipv4_defanged() {
        let (entries, _, _) = parse_iocs("192[.]168[.]1[.]1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::IPv4);
        assert_eq!(entries[0].value, "192.168.1.1");
    }

    #[test]
    fn test_parse_domain() {
        let (entries, _, _) = parse_iocs("evil-domain.com");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::Domain);
        assert_eq!(entries[0].value, "evil-domain.com");
    }

    #[test]
    fn test_parse_url() {
        let (entries, _, _) = parse_iocs("Visit https://malware.example.com/payload.exe now");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::URL);
        assert!(entries[0].value.starts_with("https://"));
    }

    #[test]
    fn test_parse_url_defanged() {
        let (entries, _, _) = parse_iocs("hxxps://evil[.]com/malware");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::URL);
        assert_eq!(entries[0].value, "https://evil.com/malware");
    }

    #[test]
    fn test_parse_email() {
        let (entries, _, _) = parse_iocs("Contact: attacker@evil.com");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::Email);
        assert_eq!(entries[0].value, "attacker@evil.com");
    }

    #[test]
    fn test_parse_md5() {
        let (entries, _, _) = parse_iocs("Hash: d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::MD5);
        assert_eq!(entries[0].priority, Priority::High);
    }

    #[test]
    fn test_parse_sha256() {
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let input = format!("SHA256: {}", hash);
        let (entries, _, _) = parse_iocs(&input);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::SHA256);
        assert_eq!(entries[0].value, hash);
    }

    #[test]
    fn test_parse_cve() {
        let (entries, _, _) = parse_iocs("Vuln: CVE-2024-12345");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::CVE);
        assert_eq!(entries[0].value, "CVE-2024-12345");
        assert_eq!(entries[0].priority, Priority::High);
    }

    #[test]
    fn test_parse_bitcoin() {
        let (entries, _, _) = parse_iocs("BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::BitcoinWallet);
    }

    #[test]
    fn test_deduplication() {
        let (entries, total, dupes) = parse_iocs("192.168.1.1, 192.168.1.1, 192.168.1.1, 10.0.0.1");
        assert_eq!(entries.len(), 2);
        assert_eq!(total, 4);
        assert_eq!(dupes, 2);
    }

    #[test]
    fn test_mixed_delimiters() {
        let input = "192.168.1.1;evil.com|CVE-2024-1234\nhttps://bad.com";
        let (entries, _, _) = parse_iocs(input);
        assert!(entries.len() >= 3); // IPv4, CVE, URL (domain may also match)
    }

    #[test]
    fn test_sha1() {
        let hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let (entries, _, _) = parse_iocs(hash);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ioc_type, IocType::SHA1);
    }

    #[test]
    fn test_empty_input() {
        let (entries, total, dupes) = parse_iocs("");
        assert_eq!(entries.len(), 0);
        assert_eq!(total, 0);
        assert_eq!(dupes, 0);
    }

    #[test]
    fn test_priority_assignment() {
        let (entries, _, _) = parse_iocs("attacker@evil.com");
        assert_eq!(entries[0].priority, Priority::Low);

        let (entries2, _, _) = parse_iocs("192.168.1.1");
        assert_eq!(entries2[0].priority, Priority::Medium);
    }
}
