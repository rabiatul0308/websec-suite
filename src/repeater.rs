use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use std::str::FromStr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RepeaterResult {
    pub status_line: String,
    pub elapsed_ms: u128,
    pub response_headers: String,
    pub response_body: String,
}

#[derive(Debug, Clone)]
pub struct IntruderRow {
    pub payload: String,
    pub status_code: u16,
    pub response_len: usize,
    pub elapsed_ms: u128,
    pub is_anomaly: bool,
}

pub fn get_builtin_wordlist(preset: &str) -> Vec<String> {
    match preset {
        "Auth Bypass SQLi" => vec![
            "' OR '1'='1".into(),
            "' OR 1=1-- -".into(),
            "admin'--".into(),
            "\" OR \"1\"=\"1".into(),
            "' UNION SELECT NULL--".into(),
            "') OR ('1'='1".into(),
        ],
        "Common Admin & API Paths" => vec![
            "admin".into(),
            "login".into(),
            "dashboard".into(),
            "api/v1/users".into(),
            "api/health".into(),
            "swagger.json".into(),
            "graphql".into(),
            ".env".into(),
            "storage/logs/laravel.log".into(),
        ],
        "IDOR Numeric (1..=50)" => (1..=50).map(|n| n.to_string()).collect(),
        _ => vec!["test".into(), "admin".into(), "1".into()],
    }
}

pub fn run_intruder_fuzzing(
    method_str: &str,
    url_tpl: &str,
    headers_tpl: &str,
    body_tpl: &str,
    payloads: &[String],
) -> Result<Vec<IntruderRow>, String> {
    if !url_tpl.contains("§FUZZ§")
        && !headers_tpl.contains("§FUZZ§")
        && !body_tpl.contains("§FUZZ§")
    {
        return Err(
            "Tambahkan penanda §FUZZ§ pada URL, Headers, atau Body terlebih dahulu.".into(),
        );
    }

    // Kirim baseline terlebih dahulu dengan string acak
    let baseline = send_custom_request(
        method_str,
        &url_tpl.replace("§FUZZ§", "__baseline_probe__"),
        &headers_tpl.replace("§FUZZ§", "__baseline_probe__"),
        &body_tpl.replace("§FUZZ§", "__baseline_probe__"),
    )?;

    let base_status = baseline
        .status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let base_len = baseline.response_body.len();

    let mut rows = Vec::new();
    for pay in payloads {
        let trimmed_pay = pay.trim();
        if trimmed_pay.is_empty() {
            continue;
        }
        let u = url_tpl.replace("§FUZZ§", trimmed_pay);
        let h = headers_tpl.replace("§FUZZ§", trimmed_pay);
        let b = body_tpl.replace("§FUZZ§", trimmed_pay);

        if let Ok(res) = send_custom_request(method_str, &u, &h, &b) {
            let status_code = res
                .status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            let resp_len = res.response_body.len();
            let len_diff = (resp_len as isize - base_len as isize).unsigned_abs();
            let is_anomaly = status_code != base_status || len_diff > 60;

            rows.push(IntruderRow {
                payload: trimmed_pay.to_string(),
                status_code,
                response_len: resp_len,
                elapsed_ms: res.elapsed_ms,
                is_anomaly,
            });
        }
    }

    Ok(rows)
}

pub fn send_custom_request(
    method_str: &str,
    url: &str,
    raw_headers: &str,
    body: &str,
) -> Result<RepeaterResult, String> {
    let method = Method::from_str(method_str.trim().to_uppercase().as_str())
        .map_err(|_| format!("HTTP Method tidak valid: {}", method_str))?;

    let target_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.trim().to_string()
    } else {
        format!("https://{}", url.trim())
    };

    let mut header_map = HeaderMap::new();
    for line in raw_headers.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let name = HeaderName::from_bytes(k.trim().as_bytes())
                .map_err(|e| format!("Nama header tidak valid '{}': {}", k, e))?;
            let val = HeaderValue::from_str(v.trim())
                .map_err(|e| format!("Nilai header tidak valid '{}': {}", v, e))?;
            header_map.insert(name, val);
        }
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(12))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;

    let mut req = client.request(method, &target_url).headers(header_map);
    if !body.is_empty() {
        req = req.body(body.to_string());
    }

    let start = Instant::now();
    let resp = req
        .send()
        .map_err(|e| format!("Gagal mengirim request: {}", e))?;
    let elapsed_ms = start.elapsed().as_millis();

    let status_line = format!(
        "HTTP/1.1 {} {}",
        resp.status().as_u16(),
        resp.status().canonical_reason().unwrap_or("")
    );

    let mut hdr_out = String::new();
    for (k, v) in resp.headers() {
        hdr_out.push_str(&format!("{}: {}\n", k, v.to_str().unwrap_or("<binary>")));
    }

    let response_body = resp.text().unwrap_or_default();

    Ok(RepeaterResult {
        status_line,
        elapsed_ms,
        response_headers: hdr_out,
        response_body,
    })
}

pub fn decode_jwt_token(token: &str) -> String {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() < 2 {
        return "Format JWT tidak valid (harus memiliki minimal Header.Payload).".to_string();
    }

    let header_json = URL_SAFE_NO_PAD
        .decode(parts[0])
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| "<Gagal decode Base64URL Header>".to_string());

    let payload_json = URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| "<Gagal decode Base64URL Payload>".to_string());

    let alg_warning = if header_json.to_lowercase().contains("\"none\"") {
        "\n[CRITICAL WARNING] Algoritma 'none' terdeteksi pada header JWT — rentan bypass autentikasi!"
    } else {
        ""
    };

    format!(
        "=== JWT HEADER ===\n{}\n\n=== JWT PAYLOAD ===\n{}{}",
        header_json, payload_json, alg_warning
    )
}

pub fn transform_text(mode: &str, input: &str) -> String {
    match mode {
        "Base64 Encode" => STANDARD.encode(input.as_bytes()),
        "Base64 Decode" => STANDARD
            .decode(input.trim())
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| "Error: Input bukan string Base64 yang valid.".into()),
        "URL Encode" => url::form_urlencoded::byte_serialize(input.as_bytes()).collect::<String>(),
        "URL Decode" => url::form_urlencoded::parse(input.as_bytes())
            .map(|(k, v)| {
                if v.is_empty() {
                    k.to_string()
                } else {
                    format!("{}={}", k, v)
                }
            })
            .collect::<Vec<_>>()
            .join("&"),
        "JWT Inspector" => decode_jwt_token(input),
        _ => input.to_string(),
    }
}
