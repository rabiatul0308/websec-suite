use crate::forensic_proof::ForensicStamp;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, HOST};
use reqwest::Method;
use serde::Serialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct SniffedPacketEntry {
    pub id: usize,
    pub client_addr: String,
    pub method: String,
    pub target_url: String,
    pub response_status: u16,
    pub extracted_jwt: Option<String>,
    pub provenance_findings: Vec<String>,
    pub raw_request_preview: String,
    pub raw_response_preview: String,
    pub proof: ForensicStamp,
}

#[derive(Clone)]
pub struct SnifferController {
    pub is_running: Arc<AtomicBool>,
    pub active_upstream: Arc<Mutex<String>>,
    pub captured: Arc<Mutex<Vec<SniffedPacketEntry>>>,
}

impl SnifferController {
    pub fn new() -> Self {
        Self {
            is_running: Arc::new(AtomicBool::new(false)),
            active_upstream: Arc::new(Mutex::new(String::new())),
            captured: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn set_upstream(&self, new_target: &str) {
        let cleaned = normalize_upstream_url(new_target);
        if let Ok(mut guard) = self.active_upstream.lock() {
            *guard = cleaned;
        }
    }

    pub fn start(&self, bind_addr: String, initial_upstream: String) -> Result<(), String> {
        if self.is_running.load(Ordering::SeqCst) {
            self.set_upstream(&initial_upstream);
            return Ok(());
        }

        self.set_upstream(&initial_upstream);

        let listener = TcpListener::bind(&bind_addr)
            .map_err(|e| format!("Gagal bind sniffer ke {}: {}", bind_addr, e))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("Gagal set nonblocking: {}", e))?;

        self.is_running.store(true, Ordering::SeqCst);
        let running_flag = self.is_running.clone();
        let store = self.captured.clone();
        let upstream_arc = self.active_upstream.clone();

        thread::spawn(move || {
            let client = Client::builder()
                .timeout(Duration::from_secs(12))
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| Client::new());

            while running_flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, peer_addr)) => {
                        let c_clone = client.clone();
                        let s_clone = store.clone();
                        let up_clone = upstream_arc.clone();
                        thread::spawn(move || {
                            handle_proxy_connection(
                                stream,
                                peer_addr.to_string(),
                                &up_clone,
                                &c_clone,
                                &s_clone,
                            );
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(40));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.captured.lock() {
            guard.clear();
        }
    }
}

fn normalize_upstream_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    }
}

fn handle_proxy_connection(
    mut client_stream: TcpStream,
    peer_addr: String,
    upstream_arc: &Arc<Mutex<String>>,
    http_client: &Client,
    store: &Arc<Mutex<Vec<SniffedPacketEntry>>>,
) {
    let _ = client_stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(match client_stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method_str = parts[0].to_string();
    let raw_target = parts[1].to_string();

    if method_str.eq_ignore_ascii_case("CONNECT") {
        let msg = "HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain\r\nContent-Length: 92\r\n\r\nGunakan Dynamic Gateway: buka http://127.0.0.1:8888/https://link-target.com di browser.";
        let _ = client_stream.write_all(msg.as_bytes());
        return;
    }

    let mut current_upstream = upstream_arc.lock().map(|g| g.clone()).unwrap_or_default();

    let effective_path =
        if raw_target.starts_with("/http://") || raw_target.starts_with("/https://") {
            let embedded_url_str = raw_target.trim_start_matches('/');
            if let Ok(parsed) = Url::parse(embedded_url_str) {
                let new_base = format!(
                    "{}://{}{}",
                    parsed.scheme(),
                    parsed.host_str().unwrap_or(""),
                    parsed.port().map(|p| format!(":{}", p)).unwrap_or_default()
                );
                if let Ok(mut guard) = upstream_arc.lock() {
                    *guard = new_base.clone();
                }
                current_upstream = new_base;

                let mut p = parsed.path().to_string();
                if let Some(q) = parsed.query() {
                    p.push('?');
                    p.push_str(q);
                }
                p
            } else {
                raw_target.clone()
            }
        } else {
            raw_target.clone()
        };

    let mut headers_raw = Vec::new();
    let mut header_map = HeaderMap::new();
    let mut host_header = String::new();
    let mut content_length: usize = 0;
    let mut provenance_findings = Vec::new();
    let mut extracted_jwt: Option<String> = None;

    let upstream_host = if !current_upstream.is_empty() {
        Url::parse(&current_upstream)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_default()
    } else {
        String::new()
    };

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        headers_raw.push(trimmed.to_string());

        if let Some((k, v)) = trimmed.split_once(':') {
            let key_clean = k.trim();
            let val_clean = v.trim();
            let key_lower = key_clean.to_lowercase();

            if key_lower == "host" {
                host_header = val_clean.to_string();
                if !upstream_host.is_empty() {
                    if let Ok(hv) = HeaderValue::from_str(&upstream_host) {
                        header_map.insert(HOST, hv);
                    }
                    continue;
                }
            } else if key_lower == "content-length" {
                content_length = val_clean.parse::<usize>().unwrap_or(0);
            } else if key_lower == "authorization" {
                provenance_findings.push(format!(
                    "Provenance [Request Header Authorization]: {}",
                    truncate_str(val_clean, 72)
                ));
                if extracted_jwt.is_none() {
                    extracted_jwt = extract_jwt_candidate(val_clean);
                }
            } else if key_lower == "cookie" {
                if let Some(jwt) = extract_jwt_candidate(val_clean) {
                    provenance_findings.push(
                        "Provenance [Request Cookie]: JWT Token (eyJ...) terdeteksi pada sesi klien".into(),
                    );
                    if extracted_jwt.is_none() {
                        extracted_jwt = Some(jwt);
                    }
                }
            }

            if key_lower != "proxy-connection" && key_lower != "accept-encoding" {
                if let (Ok(hn), Ok(hv)) = (
                    HeaderName::from_bytes(key_clean.as_bytes()),
                    HeaderValue::from_str(val_clean),
                ) {
                    header_map.insert(hn, hv);
                }
            }
        }
    }

    let mut body_bytes = vec![0u8; content_length.min(131072)];
    if !body_bytes.is_empty() {
        let _ = reader.read_exact(&mut body_bytes);
    }
    let req_body_str = String::from_utf8_lossy(&body_bytes).to_string();
    if req_body_str.to_lowercase().contains("password=")
        || req_body_str.to_lowercase().contains("\"password\"")
    {
        provenance_findings.push(
            "Credential Payload Detected: Kredensial login dikirim melalui request body".into(),
        );
    }

    let full_url = if !current_upstream.is_empty() {
        let path_part =
            if effective_path.starts_with("http://") || effective_path.starts_with("https://") {
                Url::parse(&effective_path)
                    .map(|u| {
                        let mut p = u.path().to_string();
                        if let Some(q) = u.query() {
                            p.push('?');
                            p.push_str(q);
                        }
                        p
                    })
                    .unwrap_or_else(|_| "/".to_string())
            } else {
                effective_path
            };
        format!("{}{}", current_upstream, path_part)
    } else if effective_path.starts_with("http://") || effective_path.starts_with("https://") {
        effective_path
    } else {
        format!("http://{}{}", host_header, effective_path)
    };

    let method = Method::from_str(&method_str).unwrap_or(Method::GET);
    let mut outbound = http_client.request(method, &full_url).headers(header_map);
    if !body_bytes.is_empty() {
        outbound = outbound.body(body_bytes);
    }

    if let Ok(resp) = outbound.send() {
        let status = resp.status();
        let status_u16 = status.as_u16();
        let mut resp_hdr_lines = Vec::new();

        for (k, v) in resp.headers() {
            let v_str = v.to_str().unwrap_or("");
            let k_lower = k.as_str().to_lowercase();

            let rewritten_val = if k_lower == "location"
                && !current_upstream.is_empty()
                && v_str.starts_with(&current_upstream)
            {
                v_str.replacen(&current_upstream, "", 1)
            } else {
                v_str.to_string()
            };

            resp_hdr_lines.push(format!("{}: {}", k, rewritten_val));

            if k_lower == "set-cookie" {
                if let Some(jwt) = extract_jwt_candidate(v_str) {
                    provenance_findings.push(format!(
                        "Provenance [Server Set-Cookie]: Server menerbitkan JWT ({})",
                        truncate_str(v_str, 65)
                    ));
                    if extracted_jwt.is_none() {
                        extracted_jwt = Some(jwt);
                    }
                }
            }
        }

        let resp_bytes = resp.bytes().unwrap_or_default();
        let resp_body_str = String::from_utf8_lossy(&resp_bytes).to_string();
        if let Some(jwt) = extract_jwt_candidate(&resp_body_str) {
            provenance_findings.push(
                "Provenance [Server JSON/HTTP Response Body]: Token JWT diterbitkan dalam payload respons".into(),
            );
            if extracted_jwt.is_none() {
                extracted_jwt = Some(jwt);
            }
        }

        let mut wire_resp = format!(
            "HTTP/1.1 {} {}\r\n",
            status_u16,
            status.canonical_reason().unwrap_or("OK")
        );
        for h in &resp_hdr_lines {
            let hl = h.to_lowercase();
            if !hl.starts_with("transfer-encoding:")
                && !hl.starts_with("content-length:")
                && !hl.starts_with("content-encoding:")
            {
                wire_resp.push_str(h);
                wire_resp.push_str("\r\n");
            }
        }
        wire_resp.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            resp_bytes.len()
        ));
        let _ = client_stream.write_all(wire_resp.as_bytes());
        let _ = client_stream.write_all(&resp_bytes);

        let raw_req_preview = format!(
            "{} -> {}\n{}\n\n{}",
            request_line.trim(),
            full_url,
            headers_raw.join("\n"),
            truncate_str(&req_body_str, 600)
        );
        let raw_resp_preview = format!(
            "HTTP/1.1 {}\n{}\n\n{}",
            status_u16,
            resp_hdr_lines.join("\n"),
            truncate_str(&resp_body_str, 900)
        );

        let proof = ForensicStamp::generate(
            "Local Dynamic Gateway Sniffer Capture",
            &raw_req_preview,
            &raw_resp_preview,
        );

        if let Ok(mut guard) = store.lock() {
            let next_id = guard.len() + 1;
            guard.push(SniffedPacketEntry {
                id: next_id,
                client_addr: peer_addr,
                method: method_str,
                target_url: full_url,
                response_status: status_u16,
                extracted_jwt,
                provenance_findings,
                raw_request_preview: raw_req_preview,
                raw_response_preview: raw_resp_preview,
                proof,
            });
        }
    }
}

fn extract_jwt_candidate(text: &str) -> Option<String> {
    let re = Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*").ok()?;
    re.find(text).map(|m| m.as_str().to_string())
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max_chars).collect();
        format!("{}...", cut)
    }
}
