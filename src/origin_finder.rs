use crate::forensic_proof::ForensicStamp;
use reqwest::blocking::Client;
use reqwest::header::HOST;
use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::BTreeSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
pub struct OriginCandidate {
    pub ip_address: String,
    pub discovery_source: String,
    pub host_header_status: u16,
    pub title_match_score: String,
    pub is_confirmed_origin: bool,
    pub server_header: String,
    pub proof: ForensicStamp,
}

#[derive(Debug, Clone, Serialize)]
pub struct OriginDiscoveryReport {
    pub domain: String,
    pub cdn_ip: String,
    pub cdn_title: String,
    pub candidates: Vec<OriginCandidate>,
    pub elapsed_ms: u128,
}

const ORIGIN_LEAK_SUBDOMAINS: &[&str] = &[
    "direct", "origin", "cpanel", "whm", "webmail", "mail", "ftp", "ssh", "dev", "staging", "test",
    "beta", "backend", "api", "admin", "portal", "old", "v1", "v2", "server", "vps", "ns1", "ns2",
    "m", "mobile", "db", "monitor",
];

pub fn find_real_origin_ip(raw_domain: &str) -> Result<OriginDiscoveryReport, String> {
    let domain = raw_domain
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim_start_matches("www.")
        .to_lowercase();

    if domain.is_empty() || !domain.contains('.') {
        return Err("Masukkan root domain yang valid (mis. example.com).".into());
    }

    let start = Instant::now();
    let client = Client::builder()
        .timeout(Duration::from_secs(6))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("WebSec-OriginVerifier/3.0")
        .build()
        .map_err(|e| e.to_string())?;

    // 1. Ambil baseline dari domain publik (CDN)
    let cdn_ip = resolve_first_ip(&domain).unwrap_or_else(|| "Unresolved".into());
    let (cdn_status, cdn_title, cdn_body_len, _) =
        fetch_with_host(&client, &domain, &domain).unwrap_or((0, String::new(), 0, String::new()));

    // 2. Kumpulkan kandidat IP unik dari DNS subdomain yang sering lupa diproxy CDN + Google DNS-over-HTTPS (MX/SPF/TXT)
    let mut ip_sources: Vec<(String, String)> = Vec::new();
    let mut seen_ips = BTreeSet::new();
    if cdn_ip != "Unresolved" {
        seen_ips.insert(cdn_ip.clone());
    }

    for sub in ORIGIN_LEAK_SUBDOMAINS {
        let fqdn = format!("{}.{}", sub, domain);
        if let Some(ip) = resolve_first_ip(&fqdn) {
            if !is_known_cdn_ip(&ip) && seen_ips.insert(ip.clone()) {
                ip_sources.push((ip, format!("Unproxied Subdomain ({})", fqdn)));
            }
        }
    }

    // Query DNS TXT / SPF / MX via Cloudflare DoH JSON untuk mencari IP server pengirim email / SPF ip4:
    for rrtype in ["TXT", "MX"] {
        let doh_url = format!(
            "https://cloudflare-dns.com/dns-query?name={}&type={}",
            domain, rrtype
        );
        if let Ok(resp) = client
            .get(&doh_url)
            .header("Accept", "application/dns-json")
            .send()
        {
            if let Ok(text) = resp.text() {
                for token in text.split(|c: char| !c.is_ascii_digit() && c != '.') {
                    if token.matches('.').count() == 3 {
                        if let Ok(parsed_ip) = token.parse::<IpAddr>() {
                            let ip_s = parsed_ip.to_string();
                            if !parsed_ip.is_loopback()
                                && !is_known_cdn_ip(&ip_s)
                                && seen_ips.insert(ip_s.clone())
                            {
                                ip_sources
                                    .push((ip_s, format!("DNS {} / SPF Record Leak", rrtype)));
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Verifikasi Aktif: Hubungi IP kandidat langsung dengan header `Host: <domain>`
    let mut candidates = Vec::new();
    for (ip, source) in ip_sources {
        let (st, title, body_len, srv_hdr) =
            fetch_with_host(&client, &ip, &domain).unwrap_or((0, String::new(), 0, "-".into()));

        let len_diff = (body_len as isize - cdn_body_len as isize).unsigned_abs();
        let title_matches = !cdn_title.is_empty() && title == cdn_title;
        let is_confirmed = st > 0
            && st == cdn_status
            && (title_matches || (cdn_body_len > 200 && len_diff <= 120));

        let score_label = if is_confirmed {
            "100% CONFIRMED ORIGIN (Host Header & DOM Match)".to_string()
        } else if st == 200 || st == 301 || st == 302 {
            format!("Potential Related Host (HTTP {}, Title: '{}')", st, title)
        } else {
            format!("Unverified / Closed HTTP (Status: {})", st)
        };

        let proof = ForensicStamp::generate(
            "Origin IP Host-Header Differential Verification",
            &format!("GET http://{}/ | Host: {}", ip, domain),
            &format!(
                "HTTP {} | Title: {} | BodyLen: {} | Server: {}",
                st, title, body_len, srv_hdr
            ),
        );

        candidates.push(OriginCandidate {
            ip_address: ip,
            discovery_source: source,
            host_header_status: st,
            title_match_score: score_label,
            is_confirmed_origin: is_confirmed,
            server_header: srv_hdr,
            proof,
        });
    }

    // Urutkan kandidat terkonfirmasi paling atas
    candidates.sort_by_key(|c| !c.is_confirmed_origin);

    Ok(OriginDiscoveryReport {
        domain,
        cdn_ip,
        cdn_title,
        candidates,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

fn fetch_with_host(
    client: &Client,
    connect_target: &str,
    virtual_host: &str,
) -> Option<(u16, String, usize, String)> {
    let title_sel = Selector::parse("title").unwrap();
    for scheme in ["http", "https"] {
        let url = format!("{}://{}/", scheme, connect_target);
        if let Ok(resp) = client.get(&url).header(HOST, virtual_host).send() {
            let status = resp.status().as_u16();
            let srv = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("Unknown")
                .to_string();
            let body = resp.text().unwrap_or_default();
            let doc = Html::parse_document(&body);
            let title = doc
                .select(&title_sel)
                .next()
                .map(|el| el.text().collect::<String>().trim().to_string())
                .unwrap_or_default();
            return Some((status, title, body.len(), srv));
        }
    }
    None
}

fn resolve_first_ip(host: &str) -> Option<String> {
    format!("{}:80", host)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|s| s.ip().to_string())
}

fn is_known_cdn_ip(ip: &str) -> bool {
    ip.starts_with("104.16.")
        || ip.starts_with("104.17.")
        || ip.starts_with("104.18.")
        || ip.starts_with("104.21.")
        || ip.starts_with("172.67.")
        || ip.starts_with("13.32.")
        || ip.starts_with("13.33.")
        || ip.starts_with("13.224.")
}
