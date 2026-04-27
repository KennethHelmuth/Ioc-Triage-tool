use crate::models::{IocType, LookupUrl};

/// Generate lookup URLs for a given IOC value and type.
/// Returns a list of LookupUrl structs with platform name and fully-formed URL.
pub fn generate_lookup_urls(value: &str, ioc_type: &IocType) -> Vec<LookupUrl> {
    match ioc_type {
        IocType::IPv4 | IocType::IPv6 => vec![
            LookupUrl {
                platform: "VirusTotal".to_string(),
                url: format!("https://www.virustotal.com/gui/ip-address/{}", value),
            },
            LookupUrl {
                platform: "AbuseIPDB".to_string(),
                url: format!("https://www.abuseipdb.com/check/{}", value),
            },
            LookupUrl {
                platform: "Shodan".to_string(),
                url: format!("https://www.shodan.io/host/{}", value),
            },
            LookupUrl {
                platform: "IPinfo".to_string(),
                url: format!("https://ipinfo.io/{}", value),
            },
            LookupUrl {
                platform: "GreyNoise".to_string(),
                url: format!("https://viz.greynoise.io/ip/{}", value),
            },
        ],

        IocType::Domain => vec![
            LookupUrl {
                platform: "VirusTotal".to_string(),
                url: format!("https://www.virustotal.com/gui/domain/{}", value),
            },
            LookupUrl {
                platform: "URLScan".to_string(),
                url: format!("https://urlscan.io/search/#{}", value),
            },
            LookupUrl {
                platform: "DomainTools".to_string(),
                url: format!("https://whois.domaintools.com/{}", value),
            },
            LookupUrl {
                platform: "Wayback Machine".to_string(),
                url: format!("https://web.archive.org/web/*/{}", value),
            },
        ],

        IocType::URL => {
            let encoded = url_encode(value);
            vec![
                LookupUrl {
                    platform: "VirusTotal".to_string(),
                    url: format!("https://www.virustotal.com/gui/url/{}", encoded),
                },
                LookupUrl {
                    platform: "URLScan".to_string(),
                    url: format!("https://urlscan.io/search/#{}", encoded),
                },
            ]
        }

        IocType::MD5 | IocType::SHA1 | IocType::SHA256 => vec![
            LookupUrl {
                platform: "VirusTotal".to_string(),
                url: format!("https://www.virustotal.com/gui/file/{}", value),
            },
            LookupUrl {
                platform: "MalwareBazaar".to_string(),
                url: format!("https://bazaar.abuse.ch/search/?query={}", value),
            },
            LookupUrl {
                platform: "Hybrid Analysis".to_string(),
                url: format!("https://www.hybrid-analysis.com/search?query={}", value),
            },
            LookupUrl {
                platform: "ANY.RUN".to_string(),
                url: format!("https://any.run/malware-trends/?search={}", value),
            },
        ],

        IocType::Email => vec![
            LookupUrl {
                platform: "HaveIBeenPwned".to_string(),
                url: format!("https://haveibeenpwned.com/account/{}", value),
            },
            LookupUrl {
                platform: "Epieos".to_string(),
                url: format!("https://epieos.com/?q={}&t=email", url_encode(value)),
            },
        ],

        IocType::CVE => {
            // Extract the numeric part after "CVE-" for exploit-db
            let without_prefix = value.strip_prefix("CVE-").unwrap_or(value);
            vec![
                LookupUrl {
                    platform: "NVD".to_string(),
                    url: format!("https://nvd.nist.gov/vuln/detail/{}", value),
                },
                LookupUrl {
                    platform: "Exploit-DB".to_string(),
                    url: format!(
                        "https://www.exploit-db.com/search?cve={}",
                        without_prefix
                    ),
                },
                LookupUrl {
                    platform: "MITRE ATT&CK".to_string(),
                    url: format!("https://attack.mitre.org/search/?query={}", value),
                },
                LookupUrl {
                    platform: "CVE Details".to_string(),
                    url: format!("https://www.cvedetails.com/cve/{}", value),
                },
            ]
        }

        IocType::BitcoinWallet => vec![
            LookupUrl {
                platform: "Blockchain.com".to_string(),
                url: format!("https://www.blockchain.com/btc/address/{}", value),
            },
            LookupUrl {
                platform: "Blockchair".to_string(),
                url: format!("https://blockchair.com/bitcoin/address/{}", value),
            },
        ],

        IocType::Unknown => Vec::new(),
    }
}

/// Simple percent-encoding for URL values.
/// Encodes characters that are not unreserved per RFC 3986.
fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}
