use crate::net_recon::HostReconReport;
use crate::scanner::ScanReport;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn escape_html(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn timestamp_slug() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn export_scan_report_files(report: &ScanReport) -> Result<(PathBuf, PathBuf), String> {
    let ts = timestamp_slug();
    let base_dir = std::env::current_dir().map_err(|e| e.to_string())?;
    let json_path = base_dir.join(format!("websec_audit_report_{}.json", ts));
    let html_path = base_dir.join(format!("websec_audit_report_{}.html", ts));

    let json_str = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    fs::write(&json_path, json_str).map_err(|e| format!("Gagal menyimpan JSON: {}", e))?;

    let mut tech_rows = String::new();
    for t in &report.tech_stack {
        tech_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            escape_html(&t.name),
            escape_html(&t.category),
            escape_html(&t.confidence),
            escape_html(&t.evidence),
        ));
    }
    if tech_rows.is_empty() {
        tech_rows =
            "<tr><td colspan='4'>Tidak ada fingerprint spesifik terdeteksi.</td></tr>".into();
    }

    let mut finding_cards = String::new();
    for f in &report.findings {
        let badge_color = match f.severity.as_str() {
            "CRITICAL" => "#b91c1c",
            "HIGH" => "#c2410c",
            "MEDIUM" => "#b45309",
            _ => "#1d4ed8",
        };
        finding_cards.push_str(&format!(
            r#"<div class="card">
                <div class="card-header">
                    <span class="badge" style="background:{};">{}</span>
                    <span class="layer">[{}]</span>
                    <strong>{} — {}</strong>
                </div>
                <p><strong>Bukti Teknis:</strong> <code>{}</code></p>
                <p><strong>Rekomendasi Perbaikan:</strong> {}</p>
            </div>"#,
            badge_color,
            escape_html(&f.severity),
            escape_html(&f.layer),
            escape_html(&f.category),
            escape_html(&f.title),
            escape_html(&f.evidence),
            escape_html(&f.remediation),
        ));
    }

    let html_doc = format!(
        r#"<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Executive Security Audit Report — WebSec-Suite</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 32px; color: #1f2937; line-height: 1.5; }}
  h1, h2 {{ color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; }}
  .summary {{ background: #f3f4f6; padding: 16px; border-radius: 8px; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
  th, td {{ border: 1px solid #d1d5db; padding: 8px 12px; text-align: left; font-size: 14px; }}
  th {{ background: #1f2937; color: #ffffff; }}
  .card {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 14px; margin-bottom: 14px; page-break-inside: avoid; }}
  .card-header {{ margin-bottom: 8px; font-size: 15px; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 6px; }}
  .layer {{ color: #4b5563; font-weight: bold; margin-right: 6px; }}
  code {{ background: #f3f4f6; padding: 2px 5px; border-radius: 4px; font-size: 13px; word-break: break-all; }}
</style>
</head>
<body>
  <h1>Executive Security Audit Report</h1>
  <div class="summary">
    <p><strong>Target URL:</strong> {}</p>
    <p><strong>HTTP Status:</strong> {} | <strong>Latency:</strong> {} ms | <strong>Server Banner:</strong> {}</p>
    <p><strong>Ringkasan Risiko:</strong> {}</p>
  </div>

  <h2>1. Technology Stack & Fingerprinting</h2>
  <table>
    <thead><tr><th>Teknologi</th><th>Kategori</th><th>Confidence</th><th>Bukti</th></tr></thead>
    <tbody>{}</tbody>
  </table>

  <h2>2. Daftar Temuan Kerentanan & Rekomendasi</h2>
  {}
</body>
</html>"#,
        escape_html(&report.target_url),
        report.status_code,
        report.response_time_ms,
        escape_html(&report.server_banner),
        escape_html(&report.risk_summary),
        tech_rows,
        finding_cards,
    );

    fs::write(&html_path, html_doc).map_err(|e| format!("Gagal menyimpan HTML: {}", e))?;
    Ok((html_path, json_path))
}

pub fn export_recon_report_files(report: &HostReconReport) -> Result<(PathBuf, PathBuf), String> {
    let ts = timestamp_slug();
    let base_dir = std::env::current_dir().map_err(|e| e.to_string())?;
    let json_path = base_dir.join(format!("websec_recon_report_{}.json", ts));
    let html_path = base_dir.join(format!("websec_recon_report_{}.html", ts));

    let json_str = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    fs::write(&json_path, json_str).map_err(|e| format!("Gagal menyimpan JSON: {}", e))?;

    let mut rows = String::new();
    for p in &report.open_ports {
        let cve_list = if p.exploits.is_empty() {
            "Tidak ada kecocokan CVE kritis".to_string()
        } else {
            p.exploits
                .iter()
                .map(|e| format!("{} (CVSS {:.1}): {}", e.cve_id, e.cvss, e.title))
                .collect::<Vec<_>>()
                .join("<br>")
        };
        rows.push_str(&format!(
            "<tr><td>{}/tcp</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
            p.port,
            escape_html(&p.state),
            escape_html(&p.service),
            escape_html(&p.version_banner),
            cve_list
        ));
    }

    let html_doc = format!(
        r#"<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Infrastructure & Service Recon Report — WebSec-Suite</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 32px; color: #1f2937; }}
  h1 {{ border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; }}
  .summary {{ background: #f3f4f6; padding: 16px; border-radius: 8px; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ border: 1px solid #d1d5db; padding: 8px 12px; text-align: left; font-size: 14px; }}
  th {{ background: #1f2937; color: #fff; }}
</style>
</head>
<body>
  <h1>Infrastructure & Service Reconnaissance Report</h1>
  <div class="summary">
    <p><strong>Target Host:</strong> {} ({})</p>
    <p><strong>Estimasi OS:</strong> {}</p>
    <p><strong>Durasi Pemindaian:</strong> {} ms</p>
  </div>
  <table>
    <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version / Banner</th><th>CVE / Exploit Audit</th></tr></thead>
    <tbody>{}</tbody>
  </table>
</body>
</html>"#,
        escape_html(&report.target_host),
        escape_html(&report.resolved_ip),
        escape_html(&report.os_guess),
        report.scan_duration_ms,
        rows
    );

    fs::write(&html_path, html_doc).map_err(|e| format!("Gagal menyimpan HTML: {}", e))?;
    Ok((html_path, json_path))
}
