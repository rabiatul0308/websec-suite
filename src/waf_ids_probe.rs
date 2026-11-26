use crate::forensic_proof::ForensicStamp;
use reqwest::blocking::Client;
use serde::Serialize;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct WafIdsReport {
    pub target_url: String,
    pub waf_detected: bool,
    pub vendor_signature: String,
    pub ips_behavior: String,
    pub baseline_status: u16,
    pub attack_probe_status: u16,
    pub rate_limit_triggered: bool,
    pub proof: ForensicStamp,
}

pub fn probe_waf_and_ids(raw_url: &str) -> Result<WafIdsReport, String> {
    let normalized = if raw_url.starts_with("http://") || raw_url.starts_with("https://") {
        raw_url.trim().to_string()
    } else {
        format!("https://{}", raw_url.trim())
    };
    let base_url = Url::parse(&normalized).map_err(|e| format!("URL tidak valid: {}", e))?;

    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .user_agent("WebSec-FirewallProbe/3.0")
        .build()
        .map_err(|e| e.to_string())?;

    // 1. Baseline Normal Request
    let base_resp = client
        .get(base_url.clone())
        .send()
        .map_err(|e| format!("Gagal menghubungi target: {}", e))?;
    let baseline_status = base_resp.status().as_u16();
    let base_headers_str = format!("{:?}", base_resp.headers()).to_lowercase();

    // 2. Differential IDS/WAF Trigger Probe (Benign-Intent Signature Test)
    let mut probe_url = base_url.clone();
    probe_url.query_pairs_mut().append_pair(
        "wsec_ids_test",
        "' UNION SELECT 1,2,3-- <script>alert(1)</script> ../../etc/passwd",
    );

    let start_probe = Instant::now();
    let (attack_probe_status, probe_headers_str, probe_body, err_kind) =
        match client.get(probe_url.clone()).send() {
            Ok(r) => {
                let st = r.status().as_u16();
                let h = format!("{:?}", r.headers()).to_lowercase();
                let b = r.text().unwrap_or_default().to_lowercase();
                (st, h, b, None)
            }
            Err(e) => (0, String::new(), String::new(), Some(e.to_string())),
        };
    let probe_ms = start_probe.elapsed().as_millis();

    let combined = format!("{} {} {}", base_headers_str, probe_headers_str, probe_body);
    let vendor_signature = if combined.contains("cf-ray") || combined.contains("cloudflare") {
        "Cloudflare WAF / CDN Edge".to_string()
    } else if combined.contains("x-amzn-waf")
        || combined.contains("awselb")
        || combined.contains("cloudfront")
    {
        "AWS WAF / CloudFront Shield".to_string()
    } else if combined.contains("incap_ses")
        || combined.contains("visid_incap")
        || combined.contains("imperva")
    {
        "Imperva Incapsula WAF".to_string()
    } else if combined.contains("sucuri") || combined.contains("x-sucuri-id") {
        "Sucuri CloudProxy WAF".to_string()
    } else if combined.contains("mod_security")
        || combined.contains("modsecurity")
        || combined.contains("not acceptable")
    {
        "ModSecurity OWASP CRS (Apache/Nginx)".to_string()
    } else if combined.contains("akamai") || combined.contains("ak_bmsc") {
        "Akamai Kona Site Defender".to_string()
    } else if attack_probe_status == 403 || attack_probe_status == 406 {
        "Generic Reverse-Proxy WAF / Custom Rule Filter".to_string()
    } else {
        "Tidak ada signature WAF komersial terdeteksi".to_string()
    };

    let ips_behavior = if let Some(err) = err_kind {
        if err.to_lowercase().contains("reset") || err.to_lowercase().contains("closed") {
            format!(
                "Active IPS TCP RST (Koneksi diputus paksa saat payload dikirim: {})",
                err
            )
        } else {
            format!(
                "Silent Packet Drop / Timeout IPS ({} ms: {})",
                probe_ms, err
            )
        }
    } else if baseline_status == 200
        && (attack_probe_status == 403 || attack_probe_status == 406 || attack_probe_status == 429)
    {
        format!(
            "Inline WAF Active Blocking (Baseline HTTP {} -> Payload HTTP {})",
            baseline_status, attack_probe_status
        )
    } else if baseline_status == 403 && attack_probe_status == 403 {
        "Strict Perimeter Block / Geo-IP / Bot Challenge (HTTP 403 pada semua request)".to_string()
    } else {
        format!(
            "Pass-Through / Permissive (Baseline HTTP {} -> Payload HTTP {})",
            baseline_status, attack_probe_status
        )
    };

    // 3. Burst Rate-Limit Check (8 rapid requests)
    let mut rate_limit_triggered = false;
    for _ in 0..8 {
        if let Ok(r) = client.get(base_url.clone()).send() {
            if r.status().as_u16() == 429 {
                rate_limit_triggered = true;
                break;
            }
        }
    }

    let waf_detected = vendor_signature != "Tidak ada signature WAF komersial terdeteksi"
        || (baseline_status == 200 && attack_probe_status == 403)
        || rate_limit_triggered;

    let proof = ForensicStamp::generate(
        "WAF / IDS / IPS Differential & Rate-Limit Audit",
        &format!("Baseline GET {} vs Probe GET {}", base_url, probe_url),
        &format!(
            "Baseline={} | Probe={} | Vendor={} | IPS={} | RateLimit429={}",
            baseline_status,
            attack_probe_status,
            vendor_signature,
            ips_behavior,
            rate_limit_triggered
        ),
    );

    Ok(WafIdsReport {
        target_url: base_url.to_string(),
        waf_detected,
        vendor_signature,
        ips_behavior,
        baseline_status,
        attack_probe_status,
        rate_limit_triggered,
        proof,
    })
}
