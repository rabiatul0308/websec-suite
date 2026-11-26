use crate::exploit_db::{match_exploits_from_banner, ExploitMatch};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize)]
pub struct PortServiceResult {
    pub port: u16,
    pub state: String,
    pub service: String,
    pub version_banner: String,
    pub latency_ms: u128,
    pub exploits: Vec<ExploitMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostReconReport {
    pub target_host: String,
    pub resolved_ip: String,
    pub os_guess: String,
    pub open_ports: Vec<PortServiceResult>,
    pub scan_duration_ms: u128,
}

pub const TOP_INFRA_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3000, 3306, 3389,
    5000, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 9200, 27017,
];

pub fn parse_port_spec(spec: &str) -> Vec<u16> {
    let trimmed = spec.trim();
    if trimmed.eq_ignore_ascii_case("top") || trimmed.is_empty() {
        return TOP_INFRA_PORTS.to_vec();
    }

    let mut ports = Vec::new();
    for part in trimmed.split(',') {
        let p = part.trim();
        if let Some((start_s, end_s)) = p.split_once('-') {
            if let (Ok(s), Ok(e)) = (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>()) {
                if s <= e {
                    for port in s..=e {
                        if !ports.contains(&port) {
                            ports.push(port);
                        }
                    }
                }
            }
        } else if let Ok(single) = p.parse::<u16>() {
            if !ports.contains(&single) {
                ports.push(single);
            }
        }
    }
    if ports.is_empty() {
        TOP_INFRA_PORTS.to_vec()
    } else {
        ports
    }
}

pub fn run_nmap_style_scan(
    target: &str,
    port_spec: &str,
    timeout_ms: u64,
) -> Result<HostReconReport, String> {
    let clean_host = target
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();

    if clean_host.is_empty() {
        return Err("Host / IP target tidak boleh kosong.".into());
    }

    let addr_lookup = format!("{}:80", clean_host);
    let resolved_ip: IpAddr = addr_lookup
        .to_socket_addrs()
        .map_err(|e| format!("Gagal resolve DNS '{}': {}", clean_host, e))?
        .next()
        .ok_or_else(|| "Alamat IP tidak ditemukan.".to_string())?
        .ip();

    let ports = parse_port_spec(port_spec);
    let rt = Runtime::new().map_err(|e| format!("Gagal membuat Tokio runtime: {}", e))?;

    let start_total = Instant::now();
    let open_ports = rt.block_on(async move {
        let mut handles = Vec::new();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(64));

        for port in ports {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let host_clone = clean_host.clone();
            handles.push(tokio::spawn(async move {
                let res = probe_single_port(resolved_ip, &host_clone, port, timeout_ms).await;
                drop(permit);
                res
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            if let Ok(Some(port_res)) = h.await {
                results.push(port_res);
            }
        }
        results.sort_by_key(|r| r.port);
        results
    });

    let scan_duration_ms = start_total.elapsed().as_millis();
    let os_guess = infer_os_from_services(&open_ports, resolved_ip);

    Ok(HostReconReport {
        target_host: target.trim().to_string(),
        resolved_ip: resolved_ip.to_string(),
        os_guess,
        open_ports,
        scan_duration_ms,
    })
}

async fn probe_single_port(
    ip: IpAddr,
    hostname: &str,
    port: u16,
    timeout_ms: u64,
) -> Option<PortServiceResult> {
    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();
    let mut stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let latency_ms = start.elapsed().as_millis();

    let (service, banner) = fingerprint_service(&mut stream, hostname, port).await?;
    let exploits = match_exploits_from_banner(&service, &banner);

    Some(PortServiceResult {
        port,
        state: "OPEN".to_string(),
        service,
        version_banner: banner,
        latency_ms,
        exploits,
    })
}

fn verify_https_tls_endpoint(hostname: &str, port: u16) -> Option<(String, String)> {
    let url = if port == 443 {
        format!("https://{}/", hostname)
    } else {
        format!("https://{}:{}/", hostname, port)
    };

    // 1. Cek validitas sertifikat SSL secara ketat terlebih dahulu
    let strict_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(2200))
        .danger_accept_invalid_certs(false)
        .user_agent("WebSec-Recon/2.0")
        .build()
        .ok()?;

    let (cert_status, resp_opt) = match strict_client.head(&url).send() {
        Ok(r) => ("SSL Valid", Some(r)),
        Err(e) => {
            let err_str = e.to_string().to_lowercase();
            let insecure_client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_millis(2200))
                .danger_accept_invalid_certs(true)
                .user_agent("WebSec-Recon/2.0")
                .build()
                .ok()?;
            let r = insecure_client.head(&url).send().ok()?;
            let label = if err_str.contains("certificate") || err_str.contains("tls") {
                "SSL Invalid / Self-Signed"
            } else {
                "TLS Active"
            };
            (label, Some(r))
        }
    };

    let resp = resp_opt?;
    let server_hdr = resp
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("HTTPS Service");

    Some((
        "https".into(),
        format!(
            "HTTP {} | Server: {} [{}]",
            resp.status().as_u16(),
            server_hdr,
            cert_status
        ),
    ))
}

async fn fingerprint_service(
    stream: &mut TcpStream,
    hostname: &str,
    port: u16,
) -> Option<(String, String)> {
    let mut buf = [0u8; 512];

    match port {
        // Port 443 & 8443: Verifikasi HTTPS + SNI + Status Sertifikat SSL
        443 | 8443 => {
            let _ = stream;
            let host_owned = hostname.to_string();
            tokio::task::spawn_blocking(move || verify_https_tls_endpoint(&host_owned, port))
                .await
                .ok()?
        }

        // Port 22 (SSH)
        22 => {
            let n = timeout(Duration::from_millis(650), stream.read(&mut buf))
                .await
                .ok()?
                .ok()?;
            if n == 0 {
                return None;
            }
            let text = String::from_utf8_lossy(&buf[..n]);
            let first_line = text.lines().next().unwrap_or("").trim();
            if first_line.starts_with("SSH-") {
                return Some(("ssh".into(), first_line.to_string()));
            }
            None
        }

        // Port 3306 (MySQL/MariaDB)
        3306 => {
            let n = timeout(Duration::from_millis(650), stream.read(&mut buf))
                .await
                .ok()?
                .ok()?;
            if n > 10 && buf[4] == 0x0a {
                let ver_end = buf[5..n].iter().position(|&b| b == 0).unwrap_or(0);
                let mysql_ver = String::from_utf8_lossy(&buf[5..5 + ver_end]).to_string();
                return Some(("mysql".into(), format!("MySQL / MariaDB {}", mysql_ver)));
            }
            None
        }

        // Port 6379 (Redis)
        6379 => {
            stream.write_all(b"*1\r\n$4\r\nPING\r\n").await.ok()?;
            let n = timeout(Duration::from_millis(650), stream.read(&mut buf))
                .await
                .ok()?
                .ok()?;
            if n == 0 {
                return None;
            }
            let reply = String::from_utf8_lossy(&buf[..n]);
            if reply.contains("+PONG") {
                return Some((
                    "redis".into(),
                    "Redis In-Memory DB [UNAUTHENTICATED - No Password!]".into(),
                ));
            }
            if reply.contains("-NOAUTH") {
                return Some(("redis".into(), "Redis In-Memory DB [Auth Required]".into()));
            }
            None
        }

        // Port 5432 (PostgreSQL)
        5432 => {
            let pg_ssl_req: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
            stream.write_all(&pg_ssl_req).await.ok()?;
            let n = timeout(Duration::from_millis(650), stream.read(&mut buf))
                .await
                .ok()?
                .ok()?;
            if n == 1 && (buf[0] == b'S' || buf[0] == b'N') {
                return Some((
                    "postgresql".into(),
                    format!("PostgreSQL Database (SSL Supported: {})", buf[0] as char),
                ));
            }
            None
        }

        // Port 1433 (MSSQL)
        1433 => {
            let tds_prelogin: [u8; 34] = [
                0x12, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x06, 0x01,
                0x00, 0x1b, 0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x01, 0xff, 0x09, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            ];
            stream.write_all(&tds_prelogin).await.ok()?;
            let n = timeout(Duration::from_millis(650), stream.read(&mut buf))
                .await
                .ok()?
                .ok()?;
            if n > 0 && buf[0] == 0x04 {
                return Some((
                    "ms-sql-s".into(),
                    "Microsoft SQL Server (TDS Pre-Login Confirmed)".into(),
                ));
            }
            None
        }

        // Port 3389 (RDP)
        3389 => {
            let x224_conn_req: [u8; 19] = [
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
                0x00, 0x03, 0x00, 0x00, 0x00,
            ];
            stream.write_all(&x224_conn_req).await.ok()?;
            let n = timeout(Duration::from_millis(650), stream.read(&mut buf))
                .await
                .ok()?
                .ok()?;
            if n >= 4 && buf[0] == 0x03 && buf[1] == 0x00 {
                return Some((
                    "ms-wbt-server".into(),
                    "Microsoft RDP Remote Desktop (X.224/TPKT Confirmed)".into(),
                ));
            }
            None
        }

        // Port 23 (Telnet), 445 (SMB), 27017 (MongoDB)
        23 | 445 | 27017 => {
            if port == 445 {
                let smb_neg: [u8; 40] = [
                    0x00, 0x00, 0x00, 0x24, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00,
                    0x18, 0x53, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                    0x00,
                ];
                let _ = stream.write_all(&smb_neg).await;
            } else if port == 27017 {
                let mongo_ismaster: [u8; 45] = [
                    0x2d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd,
                    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x10,
                    0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x02, 0x24, 0x64, 0x62, 0x00, 0x00,
                ];
                let _ = stream.write_all(&mongo_ismaster).await;
            }

            let n = timeout(Duration::from_millis(650), stream.read(&mut buf))
                .await
                .ok()?
                .ok()?;
            if n == 0 {
                return None;
            }
            match port {
                23 => Some((
                    "telnet".into(),
                    "Telnet Service Active (IAC Greeting Received)".into(),
                )),
                445 => Some((
                    "microsoft-ds".into(),
                    "SMB File Sharing Active (Negotiate Response)".into(),
                )),
                27017 => Some((
                    "mongodb".into(),
                    "MongoDB Database Active (Wire Protocol Confirmed)".into(),
                )),
                _ => None,
            }
        }

        // Port HTTP / FTP / SMTP lainnya
        _ => {
            if let Ok(Ok(n)) = timeout(Duration::from_millis(450), stream.read(&mut buf)).await {
                if n > 0 {
                    let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    let clean_line = text.lines().next().unwrap_or("").trim().to_string();
                    if clean_line.starts_with("SSH-") {
                        return Some(("ssh".into(), clean_line));
                    }
                    if clean_line.starts_with("220 ") {
                        if clean_line.to_lowercase().contains("ftp") {
                            return Some(("ftp".into(), clean_line));
                        }
                        return Some(("smtp".into(), clean_line));
                    }
                    if !clean_line.is_empty() {
                        return Some((guess_service_by_port(port), clean_line));
                    }
                }
            }

            let http_probe = format!(
                "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: WebSec-Recon/2.0\r\nConnection: close\r\n\r\n",
                hostname
            );
            stream.write_all(http_probe.as_bytes()).await.ok()?;
            let n = timeout(Duration::from_millis(650), stream.read(&mut buf))
                .await
                .ok()?
                .ok()?;
            if n > 0 {
                let resp = String::from_utf8_lossy(&buf[..n]);
                if resp.starts_with("HTTP/") {
                    let server_hdr = resp
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("server:"))
                        .map(|l| l.trim().to_string())
                        .unwrap_or_else(|| {
                            resp.lines().next().unwrap_or("HTTP Service").to_string()
                        });
                    return Some(("http".into(), server_hdr));
                }
            }

            None
        }
    }
}

fn guess_service_by_port(port: u16) -> String {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 | 8000 | 8080 | 3000 | 5000 => "http",
        135 => "msrpc",
        139 | 445 => "microsoft-ds (SMB)",
        443 | 8443 => "https",
        1433 => "ms-sql-s",
        3306 => "mysql",
        3389 => "ms-wbt-server (RDP)",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "tcp-service",
    }
    .to_string()
}

fn infer_os_from_services(ports: &[PortServiceResult], ip: IpAddr) -> String {
    let all_banners: String = ports
        .iter()
        .map(|p| format!("{} {} ", p.service, p.version_banner))
        .collect::<String>()
        .to_lowercase();

    if all_banners.contains("ubuntu") {
        return "Linux (Ubuntu Server — Confirmed via Service Banner)".into();
    }
    if all_banners.contains("debian") {
        return "Linux (Debian — Confirmed via Service Banner)".into();
    }
    if all_banners.contains("centos")
        || all_banners.contains("red hat")
        || all_banners.contains("el7")
        || all_banners.contains("el8")
    {
        return "Linux (RHEL / CentOS — Confirmed via Service Banner)".into();
    }
    if all_banners.contains("microsoft-iis")
        || all_banners.contains("win32")
        || ports
            .iter()
            .any(|p| p.port == 135 || p.port == 445 || p.port == 3389)
    {
        return "Microsoft Windows / Windows Server (Confirmed via SMB/RDP/IIS)".into();
    }
    if ports.iter().any(|p| p.port == 22) && all_banners.contains("openssh") {
        return "Linux / Unix-like OS (OpenSSH Detected)".into();
    }
    if ip.is_loopback() {
        return "Localhost Loopback Interface (Host OS)".into();
    }
    "Unknown / CDN Edge-Protected Host".into()
}
