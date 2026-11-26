use reqwest::blocking::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
pub struct SubdomainEntry {
    pub subdomain: String,
    pub resolved_ip: String,
    pub origin_type: String,
    pub http_status: u16,
    pub page_title: String,
    pub server_header: String,
    pub target_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubdomainReport {
    pub root_domain: String,
    pub total_candidates: usize,
    pub active_hosts: Vec<SubdomainEntry>,
    pub elapsed_ms: u128,
}

#[derive(Deserialize)]
struct CrtShRecord {
    name_value: String,
}

const COMMON_SUBDOMAIN_WORDLIST: &[&str] = &[
    "www",
    "api",
    "lms",
    "admin",
    "administrator",
    "siswa",
    "guru",
    "portal",
    "siakad",
    "backend",
    "dev",
    "staging",
    "test",
    "uat",
    "app",
    "dashboard",
    "auth",
    "sso",
    "login",
    "mail",
    "webmail",
    "cdn",
    "assets",
    "media",
    "static",
    "db",
    "phpmyadmin",
    "gitlab",
    "git",
    "jenkins",
    "grafana",
    "monitor",
    "vpn",
    "mobile",
    "m",
    "elearning",
    "ppdb",
    "perpustakaan",
    "library",
    "repo",
    "repository",
    "sim",
    "erp",
    "hrd",
    "keuangan",
];

pub fn discover_subdomains(raw_domain: &str, use_crt_sh: bool) -> Result<SubdomainReport, String> {
    let root_domain = raw_domain
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

    if root_domain.is_empty() || !root_domain.contains('.') {
        return Err(
            "Masukkan root domain yang valid (contoh: sekolah.sch.id atau example.com).".into(),
        );
    }

    let start = Instant::now();
    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .user_agent("WebSec-SubdomainRecon/2.0")
        .build()
        .map_err(|e| e.to_string())?;

    let mut candidates = BTreeSet::new();
    candidates.insert(root_domain.clone());

    for prefix in COMMON_SUBDOMAIN_WORDLIST {
        candidates.insert(format!("{}.{}", prefix, root_domain));
    }

    // Passive Certificate Transparency Lookup via crt.sh
    if use_crt_sh {
        let crt_url = format!("https://crt.sh/?q=%25.{}&output=json", root_domain);
        if let Ok(resp) = client.get(&crt_url).send() {
            if resp.status().is_success() {
                if let Ok(text) = resp.text() {
                    if let Ok(records) = serde_json::from_str::<Vec<CrtShRecord>>(&text) {
                        for rec in records {
                            for line in rec.name_value.lines() {
                                let cleaned = line.trim().trim_start_matches("*.").to_lowercase();
                                if cleaned.ends_with(&root_domain) && !cleaned.contains('*') {
                                    candidates.insert(cleaned);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let total_candidates = candidates.len();
    let mut active_hosts = Vec::new();

    for sub in candidates {
        let lookup = format!("{}:80", sub);
        if let Ok(mut addrs) = lookup.to_socket_addrs() {
            if let Some(sock) = addrs.next() {
                let ip_str = sock.ip().to_string();
                let (status, title, server_hdr, working_url) = probe_subdomain_http(&client, &sub);
                let origin_type = classify_origin_vs_cdn(&ip_str, &server_hdr);

                active_hosts.push(SubdomainEntry {
                    subdomain: sub,
                    resolved_ip: ip_str,
                    origin_type,
                    http_status: status,
                    page_title: title,
                    server_header: server_hdr,
                    target_url: working_url,
                });
            }
        }
    }

    Ok(SubdomainReport {
        root_domain,
        total_candidates,
        active_hosts,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

fn probe_subdomain_http(client: &Client, host: &str) -> (u16, String, String, String) {
    let title_sel = Selector::parse("title").unwrap();

    for scheme in ["https", "http"] {
        let url = format!("{}://{}", scheme, host);
        if let Ok(resp) = client.get(&url).send() {
            let status = resp.status().as_u16();
            let server_hdr = resp
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
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| "(No HTML Title)".to_string());

            return (status, title, server_hdr, url);
        }
    }

    (
        0,
        "DNS Resolved (Non-HTTP Service)".into(),
        "-".into(),
        format!("http://{}", host),
    )
}

fn classify_origin_vs_cdn(ip: &str, server_hdr: &str) -> String {
    let srv = server_hdr.to_lowercase();
    if srv.contains("cloudflare")
        || ip.starts_with("104.16.")
        || ip.starts_with("104.17.")
        || ip.starts_with("104.18.")
        || ip.starts_with("104.21.")
        || ip.starts_with("172.67.")
    {
        return "CDN (Cloudflare Proxy)".into();
    }
    if srv.contains("cloudfront") || srv.contains("amazons3") {
        return "CDN / Cloud (AWS CloudFront/S3)".into();
    }
    if srv.contains("vercel") || srv.contains("netlify") {
        return "Edge PaaS (Vercel/Netlify)".into();
    }
    "Direct Origin IP (Non-CDN)".into()
}
