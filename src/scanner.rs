use crate::exploit_db::{detect_tech_stack, TechFingerprint};
use crate::net_recon::run_nmap_style_scan;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, CONTENT_TYPE, ORIGIN, REFERER, USER_AGENT};
use scraper::{Html, Selector};
use serde::Serialize;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct VulnFinding {
    pub severity: String,
    pub layer: String,
    pub category: String,
    pub title: String,
    pub evidence: String,
    pub remediation: String,
}

impl VulnFinding {
    fn new(
        severity: impl Into<String>,
        layer: impl Into<String>,
        category: impl Into<String>,
        title: impl Into<String>,
        evidence: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            severity: severity.into(),
            layer: layer.into(),
            category: category.into(),
            title: title.into(),
            evidence: evidence.into(),
            remediation: remediation.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub target_url: String,
    pub status_code: u16,
    pub response_time_ms: u128,
    pub server_banner: String,
    pub tech_stack: Vec<TechFingerprint>,
    pub forms_found: usize,
    pub links_found: usize,
    pub risk_summary: String,
    pub findings: Vec<VulnFinding>,
}

#[derive(Debug, Clone)]
struct Soft404Baseline {
    is_spa_fallback: bool,
    body_len: usize,
    head_prefix: String,
}

impl Soft404Baseline {
    fn matches_fallback(&self, content_type: &str, body: &str) -> bool {
        if !self.is_spa_fallback {
            return false;
        }
        let ct_lower = content_type.to_lowercase();
        if ct_lower.contains("text/html") {
            return true;
        }
        let prefix: String = body.chars().take(180).collect();
        let len_diff = (body.len() as isize - self.body_len as isize).unsigned_abs();
        (!self.head_prefix.is_empty() && prefix == self.head_prefix) || len_diff <= 64
    }
}

fn capture_soft404_baseline(client: &Client, base_url: &Url) -> Soft404Baseline {
    if let Ok(probe_url) = base_url.join("/__websec_404_probe_99481__") {
        if let Ok(resp) = client.get(probe_url).send() {
            let status = resp.status().as_u16();
            let ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            let body = resp.text().unwrap_or_default();
            if status == 200 && ct.contains("text/html") {
                return Soft404Baseline {
                    is_spa_fallback: true,
                    body_len: body.len(),
                    head_prefix: body.chars().take(180).collect(),
                };
            }
        }
    }
    Soft404Baseline {
        is_spa_fallback: false,
        body_len: 0,
        head_prefix: String::new(),
    }
}

fn detect_waf_block(status_code: u16, headers: &HeaderMap, findings: &mut Vec<VulnFinding>) {
    if status_code != 403 {
        return;
    }

    let server = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    let has_cf_mitigated = headers.contains_key("cf-mitigated");
    let has_amzn_waf =
        headers.contains_key("x-amzn-waf-action") || headers.contains_key("x-amzn-errortype");

    if has_cf_mitigated
        || server.contains("cloudflare")
        || has_amzn_waf
        || server.contains("awselb")
        || server.contains("cloudfront")
    {
        let waf_vendor = if has_cf_mitigated || server.contains("cloudflare") {
            "Cloudflare WAF"
        } else {
            "AWS WAF / CloudFront"
        };

        findings.push(VulnFinding::new(
            "INFO",
            "Server Infra",
            "WAF / CDN Protection",
            format!("Active Scanning Blocked by {} (HTTP 403)", waf_vendor),
            format!(
                "Respons awal target mengembalikan 403 Forbidden dengan signature {} (Server: '{}').",
                waf_vendor, server
            ),
            "Pemindaian aktif dibatasi oleh WAF. Lakukan pengujian terhadap origin server langsung di lingkungan staging/whitelist.",
        ));
    }
}

pub fn run_full_scan(raw_url: &str, active_fuzzing: bool) -> Result<ScanReport, String> {
    let normalized = if raw_url.starts_with("http://") || raw_url.starts_with("https://") {
        raw_url.trim().to_string()
    } else {
        format!("https://{}", raw_url.trim())
    };

    let parsed_url = Url::parse(&normalized).map_err(|e| format!("URL tidak valid: {}", e))?;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("WebSec-Suite/2.0 (Full-Stack Differential Security & Infra Auditor)")
        .build()
        .map_err(|e| format!("Gagal membuat HTTP client: {}", e))?;

    let start = Instant::now();
    let resp = client
        .get(parsed_url.clone())
        .send()
        .map_err(|e| format!("Gagal menghubungi target: {}", e))?;
    let elapsed = start.elapsed().as_millis();

    let status_code = resp.status().as_u16();
    let headers = resp.headers().clone();
    let server_banner = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Tidak terungkap")
        .to_string();

    let cookies: Vec<String> = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    let body = resp.text().unwrap_or_default();
    let tech_stack = detect_tech_stack(&headers, &body, &cookies);
    let mut findings = Vec::new();

    detect_waf_block(status_code, &headers, &mut findings);

    // === BAGIAN 1: AUDIT PASIF SISI APLIKASI WEB & TLS ===
    audit_security_headers_and_tls(&headers, &parsed_url, &mut findings);
    audit_auth_and_sessions(&headers, &body, &parsed_url, &mut findings);
    audit_cors(&client, &parsed_url, &mut findings);
    let (forms_found, links_found) =
        audit_html_forms_uploads_secrets(&body, &parsed_url, &mut findings);

    // === BAGIAN 2: AUDIT AKTIF DIFFERENTIAL, MISCONFIG & INFRASTRUKTUR SERVER ===
    if active_fuzzing {
        let soft404 = capture_soft404_baseline(&client, &parsed_url);
        audit_access_control_idor(&client, &parsed_url, &soft404, &mut findings);
        probe_hidden_files_and_misconfigs(&client, &parsed_url, &soft404, &mut findings);
        fuzz_inputs_and_headers(&client, &parsed_url, &mut findings);
        audit_server_ports_ssh_and_db(&client, &parsed_url, &soft404, &mut findings);
    }

    audit_server_hardening_baseline(&parsed_url, &headers, &mut findings);

    let crit_count = findings.iter().filter(|f| f.severity == "CRITICAL").count();
    let high_count = findings.iter().filter(|f| f.severity == "HIGH").count();
    let med_count = findings.iter().filter(|f| f.severity == "MEDIUM").count();
    let low_count = findings
        .iter()
        .filter(|f| f.severity == "LOW" || f.severity == "INFO")
        .count();

    let risk_summary = format!(
        "Total {} Temuan (Critical: {}, High: {}, Medium: {}, Low/Info: {})",
        findings.len(),
        crit_count,
        high_count,
        med_count,
        low_count
    );

    Ok(ScanReport {
        target_url: parsed_url.to_string(),
        status_code,
        response_time_ms: elapsed,
        server_banner,
        tech_stack,
        forms_found,
        links_found,
        risk_summary,
        findings,
    })
}

fn audit_security_headers_and_tls(headers: &HeaderMap, url: &Url, findings: &mut Vec<VulnFinding>) {
    let required = [
        (
            "content-security-policy",
            "MEDIUM",
            "Missing Content-Security-Policy (CSP)",
            "Header CSP tidak ditemukan; meningkatkan risiko XSS dan injeksi skrip eksternal.",
            "Tambahkan header Content-Security-Policy (mis. default-src 'self').",
        ),
        (
            "x-frame-options",
            "MEDIUM",
            "Missing X-Frame-Options (Clickjacking Risk)",
            "Halaman dapat dimuat di dalam <iframe> lintas domain.",
            "Set header X-Frame-Options: DENY atau SAMEORIGIN.",
        ),
        (
            "x-content-type-options",
            "LOW",
            "Missing X-Content-Type-Options",
            "Browser berpotensi melakukan MIME-sniffing.",
            "Set header X-Content-Type-Options: nosniff.",
        ),
        (
            "referrer-policy",
            "LOW",
            "Missing Referrer-Policy",
            "URL sensitif beserta parameter query berisiko bocor melalui header Referer ke pihak ketiga.",
            "Set header Referrer-Policy: strict-origin-when-cross-origin.",
        ),
    ];

    for (hdr, sev, title, ev, rem) in required {
        if !headers.contains_key(hdr) {
            findings.push(VulnFinding::new(
                sev,
                "Web App",
                "Security Headers",
                title,
                ev,
                rem,
            ));
        }
    }

    if url.scheme() == "http" {
        findings.push(VulnFinding::new(
            "HIGH",
            "Server Infra",
            "SSL/TLS & Transport",
            "Unencrypted HTTP Protocol Used",
            format!("Target diakses melalui HTTP polos ({}) tanpa enkripsi TLS.", url),
            "Pasang sertifikat SSL/TLS valid, paksa redirect HTTP -> HTTPS, dan nonaktifkan TLS 1.0/1.1.",
        ));
    } else if !headers.contains_key("strict-transport-security") {
        findings.push(VulnFinding::new(
            "MEDIUM",
            "Server Infra",
            "SSL/TLS & Transport",
            "Missing HTTP Strict Transport Security (HSTS)",
            "Koneksi HTTPS tidak menyertakan header Strict-Transport-Security.",
            "Aktifkan Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
        ));
    }
}

fn audit_auth_and_sessions(
    headers: &HeaderMap,
    body: &str,
    url: &Url,
    findings: &mut Vec<VulnFinding>,
) {
    for cookie in headers.get_all("set-cookie") {
        if let Ok(c_str) = cookie.to_str() {
            let lower = c_str.to_lowercase();
            let mut missing_flags = Vec::new();
            if !lower.contains("httponly") {
                missing_flags.push("HttpOnly");
            }
            if url.scheme() == "https" && !lower.contains("secure") {
                missing_flags.push("Secure");
            }
            if !lower.contains("samesite") {
                missing_flags.push("SameSite");
            }

            if !missing_flags.is_empty() {
                findings.push(VulnFinding::new(
                    "MEDIUM",
                    "Web App",
                    "Autentikasi & Sesi",
                    format!(
                        "Insecure Session Cookie (Missing: {})",
                        missing_flags.join(", ")
                    ),
                    format!("Set-Cookie: {}", c_str),
                    "Tambahkan flag HttpOnly, Secure, dan SameSite=Strict/Lax pada cookie sesi.",
                ));
            }
        }
    }

    let body_lower = body.to_lowercase();
    if body_lower.contains("type=\"password\"") || body_lower.contains("type='password'") {
        if !body_lower.contains("csrf") && !body_lower.contains("_token") {
            findings.push(VulnFinding::new(
                "MEDIUM",
                "Web App",
                "Autentikasi & Sesi",
                "Potential Missing Anti-CSRF Token on Authentication Form",
                "Form password tidak mengandung field tersembunyi bernama 'csrf' atau '_token'.",
                "Sertakan Anti-CSRF token unik pada setiap form autentikasi dan perubahan state.",
            ));
        }
    }
}

fn audit_cors(client: &Client, url: &Url, findings: &mut Vec<VulnFinding>) {
    if let Ok(resp) = client
        .get(url.clone())
        .header(ORIGIN, "https://evil-attacker.example")
        .send()
    {
        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let acac = resp
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if acao == "https://evil-attacker.example"
            || (acao == "*" && acac.eq_ignore_ascii_case("true"))
        {
            findings.push(VulnFinding::new(
                "HIGH",
                "Web App",
                "Security Headers & CORS",
                "Permissive CORS / Arbitrary Origin Reflection",
                format!(
                    "Access-Control-Allow-Origin: '{}' | Allow-Credentials: '{}'",
                    acao, acac
                ),
                "Batasi Access-Control-Allow-Origin hanya ke domain frontend tepercaya.",
            ));
        }
    }
}

fn audit_html_forms_uploads_secrets(
    body: &str,
    url: &Url,
    findings: &mut Vec<VulnFinding>,
) -> (usize, usize) {
    let document = Html::parse_document(body);
    let form_sel = Selector::parse("form").unwrap();
    let link_sel = Selector::parse("a[href]").unwrap();
    let input_pw_sel = Selector::parse("input[type='password']").unwrap();
    let input_file_sel = Selector::parse("input[type='file']").unwrap();

    let forms_count = document.select(&form_sel).count();
    let links_count = document.select(&link_sel).count();

    if url.scheme() == "http" && document.select(&input_pw_sel).next().is_some() {
        findings.push(VulnFinding::new(
            "HIGH",
            "Web App",
            "Autentikasi & Sesi",
            "Password Transmitted Over Cleartext HTTP",
            "Ditemukan <input type='password'> pada halaman HTTP tanpa enkripsi.",
            "Gunakan HTTPS untuk seluruh halaman yang memproses kredensial.",
        ));
    }

    for file_input in document.select(&input_file_sel) {
        let accept_attr = file_input.value().attr("accept").unwrap_or("");
        if accept_attr.trim().is_empty() || accept_attr.contains("*") {
            findings.push(VulnFinding::new(
                "MEDIUM",
                "Web App",
                "Upload File",
                "Unrestricted File Upload Input Surface",
                format!(
                    "Elemen <input type='file'> ditemukan dengan atribut accept='{}'.",
                    accept_attr
                ),
                "Validasi ekstensi whitelist (mis. .jpg,.png,.pdf), periksa magic bytes MIME di backend, dan simpan file di luar web root.",
            ));
        }
    }

    // Laravel Debug Mode (Whoops! Stacktrace / APP_KEY Exposure)
    if (body.contains("Whoops, looks like something went wrong.")
        || body.contains("Whoops! There was an error."))
        && (body.contains("APP_KEY") || body.contains("Illuminate\\"))
    {
        findings.push(VulnFinding::new(
            "CRITICAL",
            "Web App",
            "Framework Misconfiguration",
            "Laravel APP_DEBUG=true Exposed in Production",
            "Stacktrace Whoops Laravel beserta variabel environment/APP_KEY terekspos di respons error.",
            "Set APP_DEBUG=false dan APP_ENV=production pada file .env segera.",
        ));
    }

    for (pattern, label) in [
        ("AKIA", "AWS Access Key ID"),
        ("AIzaSy", "Google API Key"),
        ("-----BEGIN PRIVATE KEY-----", "Private Cryptographic Key"),
        ("sk_live_", "Stripe Live Secret Key"),
        ("DB_PASSWORD=", "Database Password Env Variable"),
        ("DATABASE_URL=", "Database Connection URI"),
    ] {
        if body.contains(pattern) {
            findings.push(VulnFinding::new(
                "CRITICAL",
                "Web App",
                "Secret & Credential Exposure",
                format!("Hardcoded {} Exposed in Response Body", label),
                format!("Pola '{}' ditemukan pada source halaman.", pattern),
                "Cabut kredensial dan pindahkan ke environment variable sisi server.",
            ));
        }
    }

    let secret_regexes = [
        (
            r#"(?i)(password|passwd|pwd|db_pass|api_secret|secret_key)\s*[:=]\s*['"][^'"]{4,}['"]"#,
            "Hardcoded Password / Secret Assignment",
        ),
        (
            r#"(?i)(mysql|postgres|postgresql|mongodb|redis|sqlserver)://[^\s'"<>]+:[^\s'"<>]+@"#,
            "Database Connection String with Embedded Credentials",
        ),
    ];

    for (pat, title) in secret_regexes {
        if let Ok(re) = Regex::new(pat) {
            if let Some(m) = re.find(body) {
                let snippet: String = m.as_str().chars().take(60).collect();
                findings.push(VulnFinding::new(
                    "CRITICAL",
                    "Web App",
                    "Secret & Credential Exposure",
                    title,
                    format!("Kredensial tertanam terdeteksi: '{}...'", snippet),
                    "Hapus password dari source code publik dan segera ganti kredensial terkait.",
                ));
            }
        }
    }

    (forms_count, links_count)
}

fn audit_access_control_idor(
    client: &Client,
    base_url: &Url,
    soft404: &Soft404Baseline,
    findings: &mut Vec<VulnFinding>,
) {
    let restricted_paths = [
        ("/admin", "Unauthenticated Access to Admin Panel (/admin)"),
        (
            "/administrator",
            "Unauthenticated Access to Administrator Panel (/administrator)",
        ),
        (
            "/dashboard",
            "Unauthenticated Access to Dashboard (/dashboard)",
        ),
        (
            "/api/users",
            "Unauthenticated User Enumeration Endpoint (/api/users)",
        ),
        (
            "/api/v1/users/1",
            "Potential Unauthenticated IDOR Endpoint (/api/v1/users/1)",
        ),
    ];

    for (path, title) in restricted_paths {
        if let Ok(target) = base_url.join(path) {
            if let Ok(resp) = client.get(target.clone()).send() {
                if resp.status().as_u16() == 200 {
                    let ct = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_lowercase();
                    let body = resp.text().unwrap_or_default();

                    if soft404.matches_fallback(&ct, &body) {
                        continue;
                    }
                    if path.starts_with("/api/") && ct.contains("text/html") {
                        continue;
                    }

                    let body_lower = body.to_lowercase();
                    if !body_lower.contains("type=\"password\"") && body.len() > 50 {
                        findings.push(VulnFinding::new(
                            "HIGH",
                            "Web App",
                            "Kontrol Akses (Authorization / IDOR)",
                            title,
                            format!(
                                "Endpoint {} mengembalikan HTTP 200 OK (Content-Type: {}) tanpa token autentikasi.",
                                target, ct
                            ),
                            "Terapkan middleware autentikasi dan validasi kepemilikan objek (RBAC/ABAC) di sisi server.",
                        ));
                    }
                }
            }
        }
    }

    for (k, v) in base_url.query_pairs() {
        let kl = k.to_lowercase();
        if (kl.contains("id")
            || kl.contains("user")
            || kl.contains("account")
            || kl.contains("order"))
            && v.chars().all(|c| c.is_ascii_digit())
            && !v.is_empty()
        {
            findings.push(VulnFinding::new(
                "INFO",
                "Web App",
                "Kontrol Akses (Authorization / IDOR)",
                format!("Sequential Numeric Identifier Detected ('{}={}')", k, v),
                format!(
                    "Parameter '{}' menggunakan ID angka berurutan yang rentan enumerasi IDOR.",
                    k
                ),
                "Gunakan UUID acak yang tidak dapat ditebak dan verifikasi hak akses user pada setiap query ID.",
            ));
        }
    }
}

fn probe_hidden_files_and_misconfigs(
    client: &Client,
    base_url: &Url,
    soft404: &Soft404Baseline,
    findings: &mut Vec<VulnFinding>,
) {
    // (path, severity, title, strict_signature, allow_html)
    let probes = [
        (
            "/.env",
            "CRITICAL",
            "Exposed Environment File (/.env)",
            "APP_KEY=",
            false,
        ),
        (
            "/.env.bak",
            "CRITICAL",
            "Exposed Environment Backup (/.env.bak)",
            "DB_",
            false,
        ),
        (
            "/.git/HEAD",
            "CRITICAL",
            "Exposed Git Repository (/.git/HEAD)",
            "ref: refs/",
            false,
        ),
        (
            "/.git/config",
            "CRITICAL",
            "Exposed Git Config (/.git/config)",
            "[core]",
            false,
        ),
        (
            "/storage/logs/laravel.log",
            "CRITICAL",
            "Exposed Laravel Application Log (/storage/logs/laravel.log)",
            "local.ERROR",
            false,
        ),
        (
            "/backup.zip",
            "CRITICAL",
            "Exposed Archive Backup (/backup.zip)",
            "PK",
            false,
        ),
        (
            "/backup.bak",
            "HIGH",
            "Exposed Backup File (/backup.bak)",
            "",
            false,
        ),
        (
            "/wp-config.php.bak",
            "CRITICAL",
            "Exposed WordPress Config Backup",
            "DB_NAME",
            false,
        ),
        (
            "/actuator/env",
            "CRITICAL",
            "Exposed Spring Boot Actuator Env (/actuator/env)",
            "propertySources",
            false,
        ),
        (
            "/actuator/health",
            "MEDIUM",
            "Exposed Spring Boot Actuator Health (/actuator/health)",
            "\"status\"",
            false,
        ),
        (
            "/server-status",
            "MEDIUM",
            "Exposed Apache Server-Status (/server-status)",
            "Apache Server Status",
            true,
        ),
        (
            "/phpinfo.php",
            "HIGH",
            "Exposed PHP Diagnostics (/phpinfo.php)",
            "PHP Version",
            true,
        ),
        (
            "/swagger.json",
            "LOW",
            "Exposed OpenAPI/Swagger Schema",
            "\"openapi\"",
            false,
        ),
    ];

    for (path, sev, title, signature, allow_html) in probes {
        if let Ok(target) = base_url.join(path) {
            if let Ok(resp) = client.get(target.clone()).send() {
                if resp.status().as_u16() == 200 {
                    let ct = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_lowercase();

                    if !allow_html && ct.contains("text/html") {
                        continue;
                    }

                    let text = resp.text().unwrap_or_default();
                    if soft404.matches_fallback(&ct, &text) {
                        continue;
                    }

                    if signature.is_empty() || text.contains(signature) {
                        findings.push(VulnFinding::new(
                            sev,
                            "Web App",
                            "File & Misconfigurasi Sensitif",
                            title,
                            format!(
                                "Endpoint {} dapat diakses publik (HTTP 200, Content-Type: {}).",
                                target, ct
                            ),
                            "Hapus file sensitif dari web root dan batasi akses endpoint internal melalui web server.",
                        ));
                    }
                }
            }
        }
    }

    // GraphQL Introspection Query Check
    if let Ok(gql_url) = base_url.join("/graphql") {
        let query_body = r#"{"query":"query{__schema{types{name}}}"}"#;
        if let Ok(resp) = client
            .post(gql_url.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(query_body)
            .send()
        {
            if resp.status().as_u16() == 200 {
                let text = resp.text().unwrap_or_default();
                if text.contains("\"__schema\"") {
                    findings.push(VulnFinding::new(
                        "MEDIUM",
                        "Web App",
                        "API & GraphQL Security",
                        "GraphQL Introspection Enabled in Production (/graphql)",
                        "Endpoint /graphql membalas query __schema secara publik.",
                        "Nonaktifkan GraphQL Introspection di lingkungan produksi.",
                    ));
                }
            }
        }
    }
}

fn fuzz_inputs_and_headers(client: &Client, url: &Url, findings: &mut Vec<VulnFinding>) {
    let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

    let baseline_body = client
        .get(url.clone())
        .send()
        .and_then(|r| r.text())
        .unwrap_or_default();

    let xss_canary = "wsec77<svg/onload=alert(1)>";
    let sqli_quote = "'";
    let cmdi_payload = ";id";

    let sql_errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "postgresql query failed",
        "sqlite3::sqlexception",
        "ora-01756",
    ];

    for (target_key, orig_val) in &pairs {
        // 1. Context-Aware Reflected XSS
        let mut xss_url = url.clone();
        {
            let mut qp = xss_url.query_pairs_mut();
            qp.clear();
            for (k, v) in &pairs {
                if k == target_key {
                    qp.append_pair(k, xss_canary);
                } else {
                    qp.append_pair(k, v);
                }
            }
        }
        if let Ok(resp) = client.get(xss_url.clone()).send() {
            let ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            let body = resp.text().unwrap_or_default();
            if ct.contains("text/html")
                && body.contains(xss_canary)
                && !baseline_body.contains(xss_canary)
            {
                findings.push(VulnFinding::new(
                    "HIGH",
                    "Web App",
                    "Validasi Input & Injeksi",
                    format!("Verified Reflected XSS on Parameter '{}'", target_key),
                    format!(
                        "Tag HTML berbahaya '{}' dirender tanpa encoding pada Content-Type: text/html ({})",
                        xss_canary, xss_url
                    ),
                    "Terapkan HTML entity encoding (< -> &lt;, > -> &gt;) sebelum merender input pengguna di HTML.",
                ));
            }
        }

        // 2. Error-Based & Differential Boolean SQL Injection
        let mut sqli_url = url.clone();
        {
            let mut qp = sqli_url.query_pairs_mut();
            qp.clear();
            for (k, v) in &pairs {
                if k == target_key {
                    qp.append_pair(k, sqli_quote);
                } else {
                    qp.append_pair(k, v);
                }
            }
        }
        let mut sqli_confirmed = false;
        if let Ok(resp) = client.get(sqli_url.clone()).send() {
            let body_lower = resp.text().unwrap_or_default().to_lowercase();
            if let Some(err_sig) = sql_errors.iter().find(|sig| {
                body_lower.contains(**sig) && !baseline_body.to_lowercase().contains(**sig)
            }) {
                sqli_confirmed = true;
                findings.push(VulnFinding::new(
                    "CRITICAL",
                    "Web App",
                    "Validasi Input & Injeksi",
                    format!("Confirmed Error-Based SQL Injection on '{}'", target_key),
                    format!(
                        "Database membocorkan syntax error '{}' (tidak muncul pada baseline) saat diuji dengan kutip tunggal.",
                        err_sig
                    ),
                    "Gunakan Prepared Statements / Parameterized Queries untuk seluruh query SQL.",
                ));
            }
        }

        // Differential Boolean Check
        if !sqli_confirmed && orig_val.chars().all(|c| c.is_ascii_digit()) && !orig_val.is_empty() {
            let mut true_url = url.clone();
            let mut false_url = url.clone();
            {
                let mut qp_t = true_url.query_pairs_mut();
                qp_t.clear();
                let mut qp_f = false_url.query_pairs_mut();
                qp_f.clear();
                for (k, v) in &pairs {
                    if k == target_key {
                        qp_t.append_pair(k, &format!("{} AND 1=1", orig_val));
                        qp_f.append_pair(k, &format!("{} AND 1=2", orig_val));
                    } else {
                        qp_t.append_pair(k, v);
                        qp_f.append_pair(k, v);
                    }
                }
            }
            if let (Ok(rt), Ok(rf)) = (client.get(true_url).send(), client.get(false_url).send()) {
                let bt = rt.text().unwrap_or_default();
                let bf = rf.text().unwrap_or_default();
                let diff_ratio = (bt.len() as isize - bf.len() as isize).unsigned_abs();
                if bt.len() == baseline_body.len() && diff_ratio > 80 {
                    findings.push(VulnFinding::new(
                        "CRITICAL",
                        "Web App",
                        "Validasi Input & Injeksi",
                        format!("Confirmed Boolean-Based Blind SQL Injection on '{}'", target_key),
                        format!(
                            "Kondisi TRUE (AND 1=1) identik dengan baseline ({} bytes), sedangkan FALSE (AND 1=2) berubah signifikan ({} bytes).",
                            bt.len(),
                            bf.len()
                        ),
                        "Gunakan Prepared Statements dan validasi tipe data integer secara ketat di backend.",
                    ));
                }
            }
        }

        // 3. OS Command Injection
        let mut cmdi_url = url.clone();
        {
            let mut qp = cmdi_url.query_pairs_mut();
            qp.clear();
            for (k, v) in &pairs {
                if k == target_key {
                    qp.append_pair(k, cmdi_payload);
                } else {
                    qp.append_pair(k, v);
                }
            }
        }
        if let Ok(resp) = client.get(cmdi_url.clone()).send() {
            let body = resp.text().unwrap_or_default();
            if ((body.contains("uid=") && body.contains("gid=")) || body.contains("root:x:0:0:"))
                && !baseline_body.contains("uid=")
            {
                findings.push(VulnFinding::new(
                    "CRITICAL",
                    "Web App",
                    "Validasi Input & Injeksi",
                    format!("Confirmed OS Command Injection on '{}'", target_key),
                    format!(
                        "Output eksekusi shell OS (uid=/gid=) muncul pada {}",
                        cmdi_url
                    ),
                    "Hindari pemanggilan shell OS (sh/cmd) dari input pengguna.",
                ));
            }
        }
    }

    // 4. HTTP Header Reflection Check
    if let Ok(resp) = client
        .get(url.clone())
        .header(USER_AGENT, xss_canary)
        .header(REFERER, xss_canary)
        .send()
    {
        let body = resp.text().unwrap_or_default();
        if body.contains(xss_canary) && !baseline_body.contains(xss_canary) {
            findings.push(VulnFinding::new(
                "MEDIUM",
                "Web App",
                "Validasi Input & Injeksi",
                "HTTP Header Injection / Reflection (User-Agent / Referer)",
                "Header User-Agent/Referer direfleksikan mentah ke halaman HTML.",
                "Encode seluruh nilai header HTTP sebelum dirender di halaman.",
            ));
        }
    }
}

fn audit_server_ports_ssh_and_db(
    client: &Client,
    base_url: &Url,
    soft404: &Soft404Baseline,
    findings: &mut Vec<VulnFinding>,
) {
    let db_web_probes = [
        (
            "/phpmyadmin/",
            "HIGH",
            "Exposed phpMyAdmin Interface",
            "phpMyAdmin",
        ),
        (
            "/adminer.php",
            "HIGH",
            "Exposed Adminer DB Manager",
            "Adminer",
        ),
        (
            "/backup.sql",
            "CRITICAL",
            "Exposed SQL Database Dump (/backup.sql)",
            "CREATE TABLE",
        ),
        (
            "/dump.sql",
            "CRITICAL",
            "Exposed SQL Database Dump (/dump.sql)",
            "INSERT INTO",
        ),
        (
            "/database.sqlite",
            "CRITICAL",
            "Exposed SQLite Database File",
            "SQLite format 3",
        ),
    ];

    for (path, sev, title, sig) in db_web_probes {
        if let Ok(target) = base_url.join(path) {
            if let Ok(resp) = client.get(target.clone()).send() {
                if resp.status().as_u16() == 200 {
                    let ct = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_lowercase();
                    let text = resp.text().unwrap_or_default();

                    if soft404.matches_fallback(&ct, &text) {
                        continue;
                    }
                    if (path.ends_with(".sql") || path.ends_with(".sqlite"))
                        && ct.contains("text/html")
                    {
                        continue;
                    }

                    if text.contains(sig) {
                        findings.push(VulnFinding::new(
                            sev,
                            "Server Infra",
                            "Port & Layanan Terbuka",
                            title,
                            format!("Layanan/file database {} terbuka untuk publik.", target),
                            "Batasi akses panel database hanya untuk IP internal/VPN dan hapus file dump SQL.",
                        ));
                    }
                }
            }
        }
    }

    if let Some(host) = base_url.host_str() {
        if let Ok(recon) =
            run_nmap_style_scan(host, "22,23,445,1433,3306,3389,5432,6379,27017", 650)
        {
            for p in recon.open_ports {
                let sev = match p.port {
                    22 | 3389 => "HIGH",
                    _ => "CRITICAL",
                };
                let cat = if p.port == 22 || p.port == 3389 {
                    "Konfigurasi SSH & Akses Remote"
                } else {
                    "Port & Layanan Terbuka"
                };
                let rem = if p.port == 22 {
                    "Batasi SSH hanya untuk IP whitelist/VPN, set 'PermitRootLogin no' & 'PasswordAuthentication no' di /etc/ssh/sshd_config, dan aktifkan Fail2Ban.".to_string()
                } else {
                    format!(
                        "Tutup port {} pada firewall publik dan ikat layanan {} hanya ke localhost / jaringan privat.",
                        p.port, p.service
                    )
                };

                findings.push(VulnFinding::new(
                    sev,
                    "Server Infra",
                    cat,
                    format!("Verified Open Service Port: {} (TCP/{})", p.service, p.port),
                    format!(
                        "Handshake terkonfirmasi pada port TCP {} ({}) di host '{}' | Banner: {}",
                        p.port, p.service, host, p.version_banner
                    ),
                    rem,
                ));

                for ex in p.exploits {
                    findings.push(VulnFinding::new(
                        "CRITICAL",
                        "Server Infra",
                        "CVE & Exploit Match",
                        format!("{} — {} (CVSS {:.1})", ex.cve_id, ex.title, ex.cvss),
                        format!("{} | PoC: {}", ex.affected_product, ex.exploit_ref),
                        ex.remediation,
                    ));
                }
            }
        }
    }
}

fn audit_server_hardening_baseline(
    url: &Url,
    headers: &HeaderMap,
    findings: &mut Vec<VulnFinding>,
) {
    if let Some(srv) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if srv.chars().any(|c| c.is_ascii_digit()) {
            findings.push(VulnFinding::new(
                "LOW",
                "Server Infra",
                "Versi OS & Perangkat Lunak",
                "Web Server Version Disclosure",
                format!("Header Server mengungkap versi spesifik: '{}'.", srv),
                "Sembunyikan versi web server (mis. 'server_tokens off;' di Nginx atau 'ServerTokens Prod' di Apache).",
            ));
        }
    }

    if let Some(powered) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        findings.push(VulnFinding::new(
            "LOW",
            "Server Infra",
            "Versi OS & Perangkat Lunak",
            "Runtime / Backend Framework Version Disclosure",
            format!("Header X-Powered-By membocorkan runtime: '{}'.", powered),
            "Nonaktifkan header X-Powered-By dan perbarui runtime ke rilis LTS terbaru.",
        ));
    }

    let host = url.host_str().unwrap_or("");
    if host == "localhost" || host == "127.0.0.1" {
        findings.push(VulnFinding::new(
            "INFO",
            "Server Infra",
            "Hak Akses File & Proses (Permissions)",
            "Local Server Hardening Checklist (Non-Root & File Permissions)",
            "Target berjalan pada host lokal; verifikasi konfigurasi hak akses OS secara langsung.",
            "Pastikan proses web server berjalan sebagai user terbatas ('www-data'), folder chmod 755, dan file konfigurasi chmod 640/600.",
        ));
    }
}
