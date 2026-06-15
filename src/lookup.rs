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
            LookupUrl {
                platform: "Cisco Talos".to_string(),
                url: format!(
                    "https://talosintelligence.com/reputation_center/lookup?search={}",
                    value
                ),
            },
        ],

        IocType::Domain => vec![
            LookupUrl {
                platform: "VirusTotal".to_string(),
                url: format!("https://www.virustotal.com/gui/domain/{}", value),
            },
            LookupUrl {
                platform: "URLScan".to_string(),
                url: format!("https://urlscan.io/search/#%22{}%22", value),
            },
            LookupUrl {
                platform: "DomainTools".to_string(),
                url: format!("https://whois.domaintools.com/{}", value),
            },
            LookupUrl {
                platform: "Wayback Machine".to_string(),
                url: format!("https://web.archive.org/web/*/{}/", value),
            },
            LookupUrl {
                platform: "Cisco Talos".to_string(),
                url: format!(
                    "https://talosintelligence.com/reputation_center/lookup?search={}",
                    value
                ),
            },
            LookupUrl {
                platform: "CRT.sh".to_string(),
                url: format!("https://crt.sh/?q={}", value),
            },
        ],

        IocType::URL => {
            let vt_id = base64_urlsafe_encode(value);
            let encoded = url_encode(value);
            vec![
                LookupUrl {
                    platform: "VirusTotal".to_string(),
                    url: format!("https://www.virustotal.com/gui/url/{}", vt_id),
                },
                LookupUrl {
                    platform: "URLScan".to_string(),
                    url: format!("https://urlscan.io/search/#%22{}%22", encoded),
                },
                LookupUrl {
                    platform: "Wayback Machine".to_string(),
                    url: format!("https://web.archive.org/web/*/{}", value),
                },
            ]
        }

        IocType::MD5 | IocType::SHA1 | IocType::SHA256 => {
            let mb_url = if value.len() == 64 {
                format!("https://bazaar.abuse.ch/sample/{}", value)
            } else if value.len() == 32 {
                format!("https://bazaar.abuse.ch/browse.php?search=md5:{}", value)
            } else {
                format!("https://bazaar.abuse.ch/browse.php?search=sha1:{}", value)
            };

            vec![
                LookupUrl {
                    platform: "VirusTotal".to_string(),
                    url: format!("https://www.virustotal.com/gui/file/{}", value),
                },
                LookupUrl {
                    platform: "MalwareBazaar".to_string(),
                    url: mb_url,
                },
                LookupUrl {
                    platform: "Hybrid Analysis".to_string(),
                    url: format!("https://www.hybrid-analysis.com/search?query={}", value),
                },
                LookupUrl {
                    platform: "ANY.RUN".to_string(),
                    url: format!("https://app.any.run/submissions/?by_text={}", value),
                },
                LookupUrl {
                    platform: "AlienVault OTX".to_string(),
                    url: format!("https://otx.alienvault.com/indicator/file/{}", value),
                },
            ]
        }

        IocType::Email => vec![
            LookupUrl {
                platform: "HaveIBeenPwned".to_string(),
                url: format!("https://haveibeenpwned.com/account/{}", value),
            },
            LookupUrl {
                platform: "Epieos".to_string(),
                url: format!("https://epieos.com/?q={}&t=email", url_encode(value)),
            },
            LookupUrl {
                platform: "IntelX".to_string(),
                url: format!("https://intelx.io/?s={}", value),
            },
        ],

        IocType::CVE => vec![
            LookupUrl {
                platform: "NVD".to_string(),
                url: format!("https://nvd.nist.gov/vuln/detail/{}", value),
            },
            LookupUrl {
                platform: "MITRE CVE".to_string(),
                url: format!("https://cve.mitre.org/cgi-bin/cvename.cgi?name={}", value),
            },
            LookupUrl {
                platform: "CVE Details".to_string(),
                url: format!("https://www.cvedetails.com/cve/{}/", value),
            },
            LookupUrl {
                platform: "MITRE ATT&CK".to_string(),
                url: format!("https://attack.mitre.org/search/?query={}", value),
            },
        ],

        IocType::BitcoinWallet => {
            let val_lower = value.to_lowercase();
            if value.starts_with("0x") || value.starts_with("0X") {
                // Ethereum
                vec![
                    LookupUrl {
                        platform: "Etherscan".to_string(),
                        url: format!("https://etherscan.io/address/{}", value),
                    },
                    LookupUrl {
                        platform: "Blockchair (ETH)".to_string(),
                        url: format!("https://blockchair.com/ethereum/address/{}", value),
                    },
                ]
            } else if value.starts_with("4") && value.len() == 95 {
                // Monero
                vec![LookupUrl {
                    platform: "XMRChain".to_string(),
                    url: format!("https://xmrchain.net/search?value={}", value),
                }]
            } else if val_lower.starts_with("ltc1")
                || (value.starts_with("L") && value.len() >= 26 && value.len() <= 35)
            {
                // Litecoin
                vec![LookupUrl {
                    platform: "Blockchair (LTC)".to_string(),
                    url: format!("https://blockchair.com/litecoin/address/{}", value),
                }]
            } else if value.starts_with("D") && value.len() >= 26 && value.len() <= 35 {
                // Dogecoin
                vec![LookupUrl {
                    platform: "Blockchair (DOGE)".to_string(),
                    url: format!("https://blockchair.com/dogecoin/address/{}", value),
                }]
            } else {
                // Bitcoin
                vec![
                    LookupUrl {
                        platform: "Blockchain.com".to_string(),
                        url: format!(
                            "https://www.blockchain.com/explorer/addresses/btc/{}",
                            value
                        ),
                    },
                    LookupUrl {
                        platform: "Blockchair".to_string(),
                        url: format!("https://blockchair.com/bitcoin/address/{}", value),
                    },
                ]
            }
        }

        IocType::Unknown => Vec::new(),
    }
}

/// Simple percent-encoding for URL values.
/// Encodes characters that are not unreserved per RFC 3986.
fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

/// Helper function to perform urlsafe base64 encoding without padding.
/// Required to generate valid direct lookup URLs for VirusTotal URL search.
fn base64_urlsafe_encode(input: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = input.as_bytes();
    let mut result = String::with_capacity((bytes.len() + 2) / 3 * 4);

    let mut chunks = bytes.chunks_exact(3);
    while let Some(chunk) = chunks.next() {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        result.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        result.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        result.push(ALPHABET[(n & 63) as usize] as char);
    }

    let remainder = chunks.remainder();
    if remainder.len() == 1 {
        let n = (remainder[0] as u32) << 16;
        result.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 63) as usize] as char);
    } else if remainder.len() == 2 {
        let n = ((remainder[0] as u32) << 16) | ((remainder[1] as u32) << 8);
        result.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        result.push(ALPHABET[((n >> 6) & 63) as usize] as char);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_urlsafe_encode() {
        assert_eq!(base64_urlsafe_encode("hello"), "aGVsbG8");
        assert_eq!(
            base64_urlsafe_encode("https://evil.com"),
            "aHR0cHM6Ly9ldmlsLmNvbQ"
        );
        assert_eq!(base64_urlsafe_encode("a"), "YQ");
        assert_eq!(base64_urlsafe_encode("ab"), "YWI");
        assert_eq!(base64_urlsafe_encode("abc"), "YWJj");
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(
            url_encode("https://evil.com/path?query=1"),
            "https%3A%2F%2Fevil.com%2Fpath%3Fquery%3D1"
        );
    }
}
