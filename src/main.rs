#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod exploit_bridge;
mod exploit_db;
mod forensic_proof;
mod net_recon;
mod netcat;
mod origin_finder;
mod repeater;
mod report_export;
mod scanner;
mod sniffer;
mod sqli_engine;
mod subdomain;
mod waf_ids_probe;

use eframe::egui;
use exploit_bridge::{build_exploit_bridge, save_msf_rc_file, ExploitBridgeReport};
use net_recon::{run_nmap_style_scan, HostReconReport};
use netcat::{execute_raw_tcp_session, NetcatResponse};
use origin_finder::{find_real_origin_ip, OriginDiscoveryReport};
use repeater::{
    get_builtin_wordlist, run_intruder_fuzzing, send_custom_request, transform_text, IntruderRow,
    RepeaterResult,
};
use report_export::{export_recon_report_files, export_scan_report_files};
use scanner::{run_full_scan, ScanReport};
use sniffer::SnifferController;
use sqli_engine::{extract_forms_from_url, run_sqli_audit, ExtractedForm, SqliAuditReport};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use subdomain::{discover_subdomains, SubdomainReport};
use waf_ids_probe::{probe_waf_and_ids, WafIdsReport};

struct WebSecApp {
    active_tab: usize,
    // Tab 0: Nmap-Style Network, OS & Exploit Recon
    recon_target: String,
    recon_ports: String,
    recon_timeout_ms: u64,
    recon_report: Option<HostReconReport>,
    recon_rx: Option<Receiver<Result<HostReconReport, String>>>,
    is_recon_running: bool,
    // Tab 1: Origin IP Unmasker
    origin_domain: String,
    origin_report: Option<OriginDiscoveryReport>,
    origin_rx: Option<Receiver<Result<OriginDiscoveryReport, String>>>,
    is_origin_running: bool,
    // Tab 2: WAF / IDS / IPS Fingerprinter
    waf_target_url: String,
    waf_report: Option<WafIdsReport>,
    waf_rx: Option<Receiver<Result<WafIdsReport, String>>>,
    is_waf_running: bool,
    // Tab 3: Subdomain & Attack Surface
    sub_domain_input: String,
    sub_use_crt: bool,
    sub_report: Option<SubdomainReport>,
    sub_rx: Option<Receiver<Result<SubdomainReport, String>>>,
    is_sub_running: bool,
    // Tab 4: SQLi Auditor
    sqli_target_url: String,
    sqli_include_forms: bool,
    sqli_enable_time: bool,
    sqli_forms_preview: Vec<ExtractedForm>,
    sqli_report: Option<SqliAuditReport>,
    sqli_rx: Option<Receiver<Result<SqliAuditReport, String>>>,
    sqli_forms_rx: Option<Receiver<Result<Vec<ExtractedForm>, String>>>,
    is_sqli_running: bool,
    // Tab 5: Full-Stack Web & Infra Scanner
    layer_filter: String,
    target_url: String,
    active_fuzzing: bool,
    scan_report: Option<ScanReport>,
    scan_rx: Option<Receiver<Result<ScanReport, String>>>,
    is_scan_running: bool,
    // Tab 6: Repeater & Intruder
    rep_submode: usize,
    rep_method: String,
    rep_url: String,
    rep_headers: String,
    rep_body: String,
    rep_result: Option<RepeaterResult>,
    rep_rx: Option<Receiver<Result<RepeaterResult, String>>>,
    is_rep_running: bool,
    intruder_preset: String,
    intruder_wordlist: String,
    intruder_rows: Vec<IntruderRow>,
    intruder_rx: Option<Receiver<Result<Vec<IntruderRow>, String>>>,
    is_intruder_running: bool,
    // Tab 7: Metasploit & SearchSploit Bridge
    msf_lhost: String,
    msf_run_searchsploit: bool,
    msf_report: Option<ExploitBridgeReport>,
    // Tab 8: Live Sniffer & Token Provenance Harvester
    sniffer_bind: String,
    sniffer_upstream: String,
    sniffer_ctrl: SnifferController,
    selected_packet_idx: Option<usize>,
    // Tab 9: Netcat & Decoder/JWT
    nc_host: String,
    nc_port: String,
    nc_payload: String,
    nc_crlf: bool,
    nc_result: Option<NetcatResponse>,
    dec_mode: String,
    dec_input: String,
    dec_output: String,
    // Status bar
    status_msg: String,
}

impl Default for WebSecApp {
    fn default() -> Self {
        let default_preset = "Auth Bypass SQLi".to_string();
        let initial_wl = get_builtin_wordlist(&default_preset).join("\n");
        Self {
            active_tab: 0,
            recon_target: "127.0.0.1".to_string(),
            recon_ports: "top".to_string(),
            recon_timeout_ms: 600,
            recon_report: None,
            recon_rx: None,
            is_recon_running: false,
            origin_domain: "example.com".to_string(),
            origin_report: None,
            origin_rx: None,
            is_origin_running: false,
            waf_target_url: "https://example.com".to_string(),
            waf_report: None,
            waf_rx: None,
            is_waf_running: false,
            sub_domain_input: "example.com".to_string(),
            sub_use_crt: true,
            sub_report: None,
            sub_rx: None,
            is_sub_running: false,
            sqli_target_url: "http://testphp.vulnweb.com/listproducts.php?cat=1".to_string(),
            sqli_include_forms: true,
            sqli_enable_time: false,
            sqli_forms_preview: Vec::new(),
            sqli_report: None,
            sqli_rx: None,
            sqli_forms_rx: None,
            is_sqli_running: false,
            layer_filter: "Semua Layer".to_string(),
            target_url: "http://testphp.vulnweb.com/listproducts.php?cat=1".to_string(),
            active_fuzzing: true,
            scan_report: None,
            scan_rx: None,
            is_scan_running: false,
            rep_submode: 0,
            rep_method: "GET".to_string(),
            rep_url: "https://httpbin.org/get?id=§FUZZ§".to_string(),
            rep_headers: "User-Agent: WebSec-Suite/3.0\nAccept: application/json".to_string(),
            rep_body: String::new(),
            rep_result: None,
            rep_rx: None,
            is_rep_running: false,
            intruder_preset: default_preset,
            intruder_wordlist: initial_wl,
            intruder_rows: Vec::new(),
            intruder_rx: None,
            is_intruder_running: false,
            msf_lhost: "127.0.0.1".to_string(),
            msf_run_searchsploit: false,
            msf_report: None,
            sniffer_bind: "127.0.0.1:8888".to_string(),
            sniffer_upstream: String::new(),
            sniffer_ctrl: SnifferController::new(),
            selected_packet_idx: None,
            nc_host: "127.0.0.1".to_string(),
            nc_port: "80".to_string(),
            nc_payload: "HEAD / HTTP/1.0\\r\\n\\r\\n".to_string(),
            nc_crlf: false,
            nc_result: None,
            dec_mode: "JWT Inspector".to_string(),
            dec_input: String::new(),
            dec_output: String::new(),
            status_msg: "WebSec-Suite v3.0 Siap. Seluruh bukti dilengkapi SHA-256 Forensic Stamp."
                .to_string(),
        }
    }
}

impl WebSecApp {
    fn any_task_running(&self) -> bool {
        self.is_recon_running
            || self.is_origin_running
            || self.is_waf_running
            || self.is_sub_running
            || self.is_sqli_running
            || self.is_scan_running
            || self.is_rep_running
            || self.is_intruder_running
            || self
                .sniffer_ctrl
                .is_running
                .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn poll_background_tasks(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.recon_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_recon_running = false;
                self.recon_rx = None;
                match result {
                    Ok(rep) => {
                        self.status_msg = format!(
                            "Recon selesai: {} ({}) — {} port terverifikasi ({} ms)",
                            rep.target_host,
                            rep.resolved_ip,
                            rep.open_ports.len(),
                            rep.scan_duration_ms
                        );
                        self.nc_host = rep.resolved_ip.clone();
                        self.recon_report = Some(rep);
                    }
                    Err(e) => self.status_msg = format!("Error Recon: {}", e),
                }
            }
        }

        if let Some(rx) = &self.origin_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_origin_running = false;
                self.origin_rx = None;
                match result {
                    Ok(rep) => {
                        let confirmed = rep
                            .candidates
                            .iter()
                            .filter(|c| c.is_confirmed_origin)
                            .count();
                        self.status_msg = format!(
                            "Origin IP Discovery selesai: {} kandidat, {} terkonfirmasi 100% ({} ms)",
                            rep.candidates.len(), confirmed, rep.elapsed_ms
                        );
                        self.origin_report = Some(rep);
                    }
                    Err(e) => self.status_msg = format!("Error Origin Finder: {}", e),
                }
            }
        }

        if let Some(rx) = &self.waf_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_waf_running = false;
                self.waf_rx = None;
                match result {
                    Ok(rep) => {
                        self.status_msg = format!(
                            "WAF/IDS Probe selesai: {} | SHA-256: {}...",
                            rep.vendor_signature,
                            &rep.proof.evidence_sha256[..16]
                        );
                        self.waf_report = Some(rep);
                    }
                    Err(e) => self.status_msg = format!("Error WAF Probe: {}", e),
                }
            }
        }

        if let Some(rx) = &self.sub_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_sub_running = false;
                self.sub_rx = None;
                match result {
                    Ok(rep) => {
                        self.status_msg = format!(
                            "Subdomain discovery selesai: {} host aktif ({} ms)",
                            rep.active_hosts.len(),
                            rep.elapsed_ms
                        );
                        self.sub_report = Some(rep);
                    }
                    Err(e) => self.status_msg = format!("Error Subdomain: {}", e),
                }
            }
        }

        if let Some(rx) = &self.sqli_forms_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_sqli_running = false;
                self.sqli_forms_rx = None;
                match result {
                    Ok(forms) => {
                        self.status_msg =
                            format!("Berhasil mengekstrak {} form HTML.", forms.len());
                        self.sqli_forms_preview = forms;
                    }
                    Err(e) => self.status_msg = format!("Error Ekstrak Form: {}", e),
                }
            }
        }

        if let Some(rx) = &self.sqli_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_sqli_running = false;
                self.sqli_rx = None;
                match result {
                    Ok(rep) => {
                        self.status_msg = format!(
                            "Audit SQLi selesai: {} temuan terkonfirmasi ({} ms)",
                            rep.findings.len(),
                            rep.elapsed_ms
                        );
                        self.sqli_forms_preview = rep.forms_discovered.clone();
                        self.sqli_report = Some(rep);
                    }
                    Err(e) => self.status_msg = format!("Error SQLi Audit: {}", e),
                }
            }
        }

        if let Some(rx) = &self.scan_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_scan_running = false;
                self.scan_rx = None;
                match result {
                    Ok(rep) => {
                        self.status_msg = format!(
                            "Audit selesai: {} ({} ms) — {}",
                            rep.target_url, rep.response_time_ms, rep.risk_summary
                        );
                        self.rep_url = rep.target_url.clone();
                        self.scan_report = Some(rep);
                    }
                    Err(e) => self.status_msg = format!("Error Audit: {}", e),
                }
            }
        }

        if let Some(rx) = &self.rep_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_rep_running = false;
                self.rep_rx = None;
                match result {
                    Ok(res) => {
                        self.status_msg = format!("{} ({} ms)", res.status_line, res.elapsed_ms);
                        self.rep_result = Some(res);
                    }
                    Err(e) => self.status_msg = format!("Error Repeater: {}", e),
                }
            }
        }

        if let Some(rx) = &self.intruder_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_intruder_running = false;
                self.intruder_rx = None;
                match result {
                    Ok(rows) => {
                        let anomalies = rows.iter().filter(|r| r.is_anomaly).count();
                        self.status_msg = format!(
                            "Intruder selesai: {} payload diuji, {} anomali terdeteksi.",
                            rows.len(),
                            anomalies
                        );
                        self.intruder_rows = rows;
                    }
                    Err(e) => self.status_msg = format!("Error Intruder: {}", e),
                }
            }
        }

        if self.any_task_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }
    }
}

impl eframe::App for WebSecApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_background_tasks(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("WEBSEC-SUITE v3.0 — Forensic-Grade Full-Stack Security & Recon Suite");
            ui.label("Origin IP Unmasker • WAF/IDS Probe • Nmap TLS Recon • Metasploit Bridge • Dynamic Gateway Sniffer");
            ui.separator();

            ui.horizontal_wrapped(|ui| {
                ui.selectable_value(&mut self.active_tab, 0, "📡 1. Nmap Recon");
                ui.selectable_value(&mut self.active_tab, 1, "🎯 2. Origin IP");
                ui.selectable_value(&mut self.active_tab, 2, "🛡️ 3. WAF/IDS/IPS");
                ui.selectable_value(&mut self.active_tab, 3, "🌐 4. Subdomains");
                ui.selectable_value(&mut self.active_tab, 4, "💉 5. SQLi Auditor");
                ui.selectable_value(&mut self.active_tab, 5, "🔍 6. Web Scanner");
                ui.selectable_value(&mut self.active_tab, 6, "🔁 7. Repeater/Intruder");
                ui.selectable_value(&mut self.active_tab, 7, "💣 8. Metasploit/Exploit");
                ui.selectable_value(&mut self.active_tab, 8, "🦈 9. Sniffer & Token");
                ui.selectable_value(&mut self.active_tab, 9, "🔌 10. Netcat & JWT");
            });
            ui.separator();

            match self.active_tab {
                0 => self.render_nmap_tab(ui),
                1 => self.render_origin_tab(ui),
                2 => self.render_waf_tab(ui),
                3 => self.render_subdomain_tab(ui),
                4 => self.render_sqli_tab(ui),
                5 => self.render_scanner_tab(ui),
                6 => self.render_repeater_intruder_tab(ui),
                7 => self.render_metasploit_tab(ui),
                8 => self.render_sniffer_tab(ui),
                _ => self.render_netcat_decoder_tab(ui),
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.separator();
                ui.horizontal(|ui| {
                    if self.any_task_running() {
                        ui.spinner();
                    }
                    ui.label(&self.status_msg);
                });
            });
        });
    }
}

impl WebSecApp {
    fn render_nmap_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Host / IP:");
            ui.add(egui::TextEdit::singleline(&mut self.recon_target).desired_width(210.0));
            ui.label("Ports ('top' / '22,80,443,3306'):");
            ui.add(egui::TextEdit::singleline(&mut self.recon_ports).desired_width(160.0));
            ui.add(egui::Slider::new(&mut self.recon_timeout_ms, 200..=2000).text("ms"));

            if ui
                .add_enabled(
                    !self.is_recon_running,
                    egui::Button::new("🚀 Scan OS, Service & CVE"),
                )
                .clicked()
            {
                let target = self.recon_target.clone();
                let ports = self.recon_ports.clone();
                let timeout_ms = self.recon_timeout_ms;
                let (tx, rx) = mpsc::channel();

                self.recon_rx = Some(rx);
                self.is_recon_running = true;
                self.status_msg = format!("Memindai protokol & TLS pada '{}'...", target);

                thread::spawn(move || {
                    let _ = tx.send(run_nmap_style_scan(&target, &ports, timeout_ms));
                });
            }
        });

        ui.add_space(6.0);
        if let Some(rep) = &self.recon_report {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(format!(
                        "Target: {} ({}) | Waktu Scan: {} ms",
                        rep.target_host, rep.resolved_ip, rep.scan_duration_ms
                    ));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("📄 Export Laporan (HTML & JSON)").clicked() {
                            match export_recon_report_files(rep) {
                                Ok((h, j)) => {
                                    self.status_msg =
                                        format!("Diekspor: {} & {}", h.display(), j.display());
                                }
                                Err(e) => self.status_msg = format!("Gagal export: {}", e),
                            }
                        }
                        if ui.button("💣 Kirim ke Metasploit Bridge ➡").clicked() {
                            self.msf_report = Some(build_exploit_bridge(
                                rep,
                                &self.msf_lhost,
                                self.msf_run_searchsploit,
                            ));
                            self.active_tab = 7;
                        }
                    });
                });
                ui.label(format!("Estimasi OS : {}", rep.os_guess));
            });

            ui.add_space(6.0);
            egui::ScrollArea::vertical().max_height(370.0).show(ui, |ui| {
                if rep.open_ports.is_empty() {
                    ui.label("Tidak ada layanan aktif yang merespons handshake pada rentang port yang dipindai.");
                } else {
                    for p in &rep.open_ports {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.strong(format!(
                                    "PORT {}/tcp  |  STATE: {}  |  SERVICE: {}  ({} ms)",
                                    p.port, p.state, p.service, p.latency_ms
                                ));
                                if ui.small_button("Kirim ke Netcat ➡").clicked() {
                                    self.nc_port = p.port.to_string();
                                    self.active_tab = 9;
                                }
                            });
                            ui.label(format!("Version / Banner : {}", p.version_banner));

                            if p.exploits.is_empty() {
                                ui.label("Exploit / CVE Audit: ✓ Tidak ada kecocokan CVE kritis pada versi banner ini.");
                            } else {
                                for ex in &p.exploits {
                                    ui.separator();
                                    ui.strong(format!(
                                        "⚠️ [EXPLOIT MATCH — CVSS {:.1}] {} : {}",
                                        ex.cvss, ex.cve_id, ex.title
                                    ));
                                    ui.label(format!("Target Terdampak : {}", ex.affected_product));
                                    ui.label(format!("Referensi PoC    : {}", ex.exploit_ref));
                                    ui.label(format!("Mitigasi         : {}", ex.remediation));
                                }
                            }
                        });
                        ui.add_space(4.0);
                    }
                }
            });
        }
    }

    fn render_origin_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Target Domain:");
            ui.add(egui::TextEdit::singleline(&mut self.origin_domain).desired_width(280.0));
            if ui
                .add_enabled(
                    !self.is_origin_running,
                    egui::Button::new("🎯 Unmask Real Origin IP"),
                )
                .clicked()
            {
                let dom = self.origin_domain.clone();
                let (tx, rx) = mpsc::channel();
                self.origin_rx = Some(rx);
                self.is_origin_running = true;
                self.status_msg = format!("Mencari IP server asli di balik CDN untuk '{}'...", dom);
                thread::spawn(move || {
                    let _ = tx.send(find_real_origin_ip(&dom));
                });
            }
        });

        ui.add_space(6.0);
        if let Some(rep) = &self.origin_report {
            ui.group(|ui| {
                ui.strong(format!(
                    "Domain: {} | Edge/CDN IP: {} | Baseline Title: '{}' ({} ms)",
                    rep.domain, rep.cdn_ip, rep.cdn_title, rep.elapsed_ms
                ));
            });

            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .max_height(370.0)
                .show(ui, |ui| {
                    if rep.candidates.is_empty() {
                        ui.label("Tidak ditemukan IP non-CDN melalui subdomain/DNS SPF leak.");
                    } else {
                        for c in &rep.candidates {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.strong(format!(
                                        "IP: {}  |  {}",
                                        c.ip_address, c.title_match_score
                                    ));
                                    if ui.small_button("Scan IP Ini di Nmap Recon ➡").clicked() {
                                        self.recon_target = c.ip_address.clone();
                                        self.active_tab = 0;
                                    }
                                });
                                ui.label(format!(
                                    "Sumber Penemuan: {} | Server: {}",
                                    c.discovery_source, c.server_header
                                ));
                                ui.label(format!(
                                    "SHA-256 Forensic Proof: {}",
                                    c.proof.evidence_sha256
                                ));
                            });
                            ui.add_space(4.0);
                        }
                    }
                });
        }
    }

    fn render_waf_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Target URL:");
            ui.add(egui::TextEdit::singleline(&mut self.waf_target_url).desired_width(420.0));
            if ui
                .add_enabled(
                    !self.is_waf_running,
                    egui::Button::new("🛡️ Probe WAF, IDS & IPS"),
                )
                .clicked()
            {
                let u = self.waf_target_url.clone();
                let (tx, rx) = mpsc::channel();
                self.waf_rx = Some(rx);
                self.is_waf_running = true;
                self.status_msg = format!("Menguji respons perimeter WAF/IDS/IPS pada '{}'...", u);
                thread::spawn(move || {
                    let _ = tx.send(probe_waf_and_ids(&u));
                });
            }
        });

        ui.add_space(8.0);
        if let Some(rep) = &self.waf_report {
            ui.group(|ui| {
                ui.strong(format!(
                    "WAF/Firewall Terdeteksi: {} — {}",
                    if rep.waf_detected { "YA" } else { "TIDAK" },
                    rep.vendor_signature
                ));
                ui.separator();
                ui.label(format!("Perilaku IPS / Blokir : {}", rep.ips_behavior));
                ui.label(format!(
                    "HTTP Status Perbandingan: Baseline = {} | Attack Signature Probe = {}",
                    rep.baseline_status, rep.attack_probe_status
                ));
                ui.label(format!(
                    "HTTP 429 Rate-Limit Triggered: {}",
                    if rep.rate_limit_triggered {
                        "YA (Aktif)"
                    } else {
                        "Tidak terpicu pada 8 burst request"
                    }
                ));
                ui.separator();
                ui.label(format!(
                    "UTC Timestamp: {} | SHA-256 Proof: {}",
                    rep.proof.capture_timestamp_utc, rep.proof.evidence_sha256
                ));
            });
        }
    }

    fn render_subdomain_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Root Domain:");
            ui.add(egui::TextEdit::singleline(&mut self.sub_domain_input).desired_width(260.0));
            ui.checkbox(&mut self.sub_use_crt, "Passive crt.sh CT Logs + DNS Brute");

            if ui
                .add_enabled(
                    !self.is_sub_running,
                    egui::Button::new("🌐 Discover Subdomains"),
                )
                .clicked()
            {
                let dom = self.sub_domain_input.clone();
                let use_crt = self.sub_use_crt;
                let (tx, rx) = mpsc::channel();

                self.sub_rx = Some(rx);
                self.is_sub_running = true;
                self.status_msg = format!("Memetakan subdomain untuk '{}'...", dom);

                thread::spawn(move || {
                    let _ = tx.send(discover_subdomains(&dom, use_crt));
                });
            }
        });

        ui.add_space(6.0);
        if let Some(rep) = &self.sub_report {
            ui.group(|ui| {
                ui.strong(format!(
                    "Root Domain: {} | Kandidat Diuji: {} | Host Aktif: {} ({} ms)",
                    rep.root_domain,
                    rep.total_candidates,
                    rep.active_hosts.len(),
                    rep.elapsed_ms
                ));
            });

            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .max_height(375.0)
                .show(ui, |ui| {
                    for entry in &rep.active_hosts {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.strong(format!(
                                    "{}  ->  {}  [{}]",
                                    entry.subdomain, entry.resolved_ip, entry.origin_type
                                ));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.small_button("🦈 Gate di Sniffer").clicked() {
                                            self.sniffer_upstream = entry.target_url.clone();
                                            let _ = self.sniffer_ctrl.start(
                                                self.sniffer_bind.clone(),
                                                entry.target_url.clone(),
                                            );
                                            self.active_tab = 8;
                                        }
                                        if ui.small_button("Web Scanner ➡").clicked() {
                                            self.target_url = entry.target_url.clone();
                                            self.active_tab = 5;
                                        }
                                        if ui.small_button("Nmap Recon ➡").clicked() {
                                            self.recon_target = entry.subdomain.clone();
                                            self.active_tab = 0;
                                        }
                                    },
                                );
                            });
                            ui.label(format!(
                                "HTTP Status: {} | Server: {} | Title: {}",
                                entry.http_status, entry.server_header, entry.page_title
                            ));
                        });
                        ui.add_space(4.0);
                    }
                });
        }
    }

    fn render_sqli_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Target URL:");
            ui.add(egui::TextEdit::singleline(&mut self.sqli_target_url).desired_width(370.0));
            ui.checkbox(&mut self.sqli_include_forms, "Auto-Form POST/GET");
            ui.checkbox(&mut self.sqli_enable_time, "Time-Based 4s (2x)");

            if ui
                .add_enabled(!self.is_sqli_running, egui::Button::new("📋 Ekstrak Form"))
                .clicked()
            {
                let u = self.sqli_target_url.clone();
                let (tx, rx) = mpsc::channel();
                self.sqli_forms_rx = Some(rx);
                self.is_sqli_running = true;
                self.status_msg = "Mengekstrak elemen <form> & input dari halaman...".into();
                thread::spawn(move || {
                    let _ = tx.send(extract_forms_from_url(&u));
                });
            }

            if ui
                .add_enabled(!self.is_sqli_running, egui::Button::new("💉 Audit SQLi"))
                .clicked()
            {
                let u = self.sqli_target_url.clone();
                let inc_forms = self.sqli_include_forms;
                let time_on = self.sqli_enable_time;
                let (tx, rx) = mpsc::channel();
                self.sqli_rx = Some(rx);
                self.is_sqli_running = true;
                self.status_msg = format!("Menjalankan differential SQLi audit pada '{}'...", u);
                thread::spawn(move || {
                    let _ = tx.send(run_sqli_audit(&u, inc_forms, time_on));
                });
            }
        });

        ui.add_space(6.0);
        if !self.sqli_forms_preview.is_empty() {
            ui.group(|ui| {
                ui.strong(format!(
                    "Form HTML Terdeteksi ({} form):",
                    self.sqli_forms_preview.len()
                ));
                for (i, f) in self.sqli_forms_preview.iter().enumerate() {
                    let field_names: Vec<String> =
                        f.inputs.iter().map(|(k, _)| k.clone()).collect();
                    ui.label(format!(
                        "#{} [{}] {} -> Fields: [{}]",
                        i + 1,
                        f.method,
                        f.action_url,
                        field_names.join(", ")
                    ));
                }
            });
            ui.add_space(4.0);
        }

        if let Some(rep) = &self.sqli_report {
            egui::ScrollArea::vertical().max_height(330.0).show(ui, |ui| {
                if rep.findings.is_empty() {
                    ui.label("✓ Tidak ditemukan kerentanan SQL Injection terkonfirmasi pada vektor GET/Form yang diuji.");
                } else {
                    for f in &rep.findings {
                        ui.group(|ui| {
                            ui.strong(format!(
                                "[{}] {} — Parameter '{}' ({})",
                                f.severity, f.technique, f.parameter_name, f.dbms_hint
                            ));
                            ui.label(format!("Vektor  : {}", f.vector_location));
                            ui.label(format!("Payload : {}", f.payload_used));
                            ui.label(format!("Bukti   : {}", f.evidence));
                            ui.label(format!("Saran   : {}", f.remediation));
                        });
                        ui.add_space(4.0);
                    }
                }
            });
        }
    }

    fn render_scanner_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Target URL:");
            ui.add(egui::TextEdit::singleline(&mut self.target_url).desired_width(390.0));
            ui.checkbox(&mut self.active_fuzzing, "Differential Active Audit");

            if ui
                .add_enabled(!self.is_scan_running, egui::Button::new("🚀 Mulai Audit"))
                .clicked()
            {
                let url = self.target_url.clone();
                let active = self.active_fuzzing;
                let (tx, rx) = mpsc::channel();

                self.scan_rx = Some(rx);
                self.is_scan_running = true;
                self.status_msg = format!("Menjalankan full-stack audit pada '{}'...", url);

                thread::spawn(move || {
                    let _ = tx.send(run_full_scan(&url, active));
                });
            }
        });

        ui.add_space(6.0);
        if let Some(rep) = &self.scan_report {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(&rep.risk_summary);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("📄 Export Laporan (HTML & JSON)").clicked() {
                            match export_scan_report_files(rep) {
                                Ok((h, j)) => {
                                    self.status_msg =
                                        format!("Diekspor: {} & {}", h.display(), j.display());
                                }
                                Err(e) => self.status_msg = format!("Gagal export: {}", e),
                            }
                        }
                        if ui.small_button("🦈 Gate di Sniffer").clicked() {
                            self.sniffer_upstream = rep.target_url.clone();
                            let _ = self
                                .sniffer_ctrl
                                .start(self.sniffer_bind.clone(), rep.target_url.clone());
                            self.active_tab = 8;
                        }
                        egui::ComboBox::from_id_salt("layer_filter_box")
                            .selected_text(&self.layer_filter)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.layer_filter,
                                    "Semua Layer".to_string(),
                                    "Semua Layer",
                                );
                                ui.selectable_value(
                                    &mut self.layer_filter,
                                    "Web App".to_string(),
                                    "Web App Saja",
                                );
                                ui.selectable_value(
                                    &mut self.layer_filter,
                                    "Server Infra".to_string(),
                                    "Server Infra Saja",
                                );
                            });
                    });
                });
                let tech_names: Vec<String> =
                    rep.tech_stack.iter().map(|t| t.name.clone()).collect();
                ui.label(format!(
                    "HTTP {} | {} ms | Tech Stack: {}",
                    rep.status_code,
                    rep.response_time_ms,
                    if tech_names.is_empty() {
                        rep.server_banner.clone()
                    } else {
                        tech_names.join(", ")
                    }
                ));
            });

            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .max_height(355.0)
                .show(ui, |ui| {
                    let filtered: Vec<_> = rep
                        .findings
                        .iter()
                        .filter(|f| {
                            self.layer_filter == "Semua Layer" || f.layer == self.layer_filter
                        })
                        .collect();

                    if filtered.is_empty() {
                        ui.label("✓ Tidak ditemukan temuan pada kategori/filter ini.");
                    } else {
                        for f in filtered {
                            ui.group(|ui| {
                                ui.strong(format!(
                                    "[{}] [{}] {} — {}",
                                    f.layer, f.severity, f.category, f.title
                                ));
                                ui.label(format!("Bukti : {}", f.evidence));
                                ui.label(format!("Saran : {}", f.remediation));
                            });
                            ui.add_space(4.0);
                        }
                    }
                });
        }
    }

    fn render_repeater_intruder_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.rep_submode, 0, "🔁 Manual Repeater");
            ui.selectable_value(&mut self.rep_submode, 1, "⚡ Intruder Fuzzer (§FUZZ§)");
        });
        ui.separator();

        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("rep_method_box")
                .selected_text(&self.rep_method)
                .width(80.0)
                .show_ui(ui, |ui| {
                    for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] {
                        ui.selectable_value(&mut self.rep_method, m.to_string(), m);
                    }
                });
            ui.add(egui::TextEdit::singleline(&mut self.rep_url).desired_width(540.0));

            if self.rep_submode == 0 {
                if ui
                    .add_enabled(!self.is_rep_running, egui::Button::new("⚡ Send Request"))
                    .clicked()
                {
                    let m = self.rep_method.clone();
                    let u = self.rep_url.clone();
                    let h = self.rep_headers.clone();
                    let b = self.rep_body.clone();
                    let (tx, rx) = mpsc::channel();
                    self.rep_rx = Some(rx);
                    self.is_rep_running = true;
                    thread::spawn(move || {
                        let _ = tx.send(send_custom_request(&m, &u, &h, &b));
                    });
                }
            } else if ui
                .add_enabled(
                    !self.is_intruder_running,
                    egui::Button::new("🚀 Start Intruder Attack"),
                )
                .clicked()
            {
                let m = self.rep_method.clone();
                let u = self.rep_url.clone();
                let h = self.rep_headers.clone();
                let b = self.rep_body.clone();
                let payloads: Vec<String> = self
                    .intruder_wordlist
                    .lines()
                    .map(|l| l.to_string())
                    .collect();
                let (tx, rx) = mpsc::channel();
                self.intruder_rx = Some(rx);
                self.is_intruder_running = true;
                self.status_msg = format!(
                    "Menjalankan Intruder fuzzing ({} payload)...",
                    payloads.len()
                );
                thread::spawn(move || {
                    let _ = tx.send(run_intruder_fuzzing(&m, &u, &h, &b, &payloads));
                });
            }
        });

        ui.add_space(6.0);
        if self.rep_submode == 0 {
            ui.columns(2, |cols| {
                cols[0].strong("Request Headers");
                cols[0].add(
                    egui::TextEdit::multiline(&mut self.rep_headers)
                        .desired_rows(7)
                        .desired_width(f32::INFINITY)
                        .code_editor(),
                );
                cols[0].add_space(4.0);
                cols[0].strong("Request Body");
                cols[0].add(
                    egui::TextEdit::multiline(&mut self.rep_body)
                        .desired_rows(7)
                        .desired_width(f32::INFINITY)
                        .code_editor(),
                );

                cols[1].strong("Response Output");
                if let Some(res) = &self.rep_result {
                    cols[1].label(format!("{} | {} ms", res.status_line, res.elapsed_ms));
                    let mut combined = format!("{}\n{}", res.response_headers, res.response_body);
                    egui::ScrollArea::vertical()
                        .max_height(310.0)
                        .show(&mut cols[1], |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut combined)
                                    .desired_rows(16)
                                    .desired_width(f32::INFINITY)
                                    .code_editor(),
                            );
                        });
                }
            });
        } else {
            ui.columns(2, |cols| {
                cols[0].horizontal(|ui| {
                    ui.strong("Wordlist Preset:");
                    egui::ComboBox::from_id_salt("intruder_preset_box")
                        .selected_text(&self.intruder_preset)
                        .show_ui(ui, |ui| {
                            for p in [
                                "Auth Bypass SQLi",
                                "Common Admin & API Paths",
                                "IDOR Numeric (1..=50)",
                            ] {
                                if ui
                                    .selectable_value(&mut self.intruder_preset, p.to_string(), p)
                                    .clicked()
                                {
                                    self.intruder_wordlist = get_builtin_wordlist(p).join("\n");
                                }
                            }
                        });
                });
                cols[0].add(
                    egui::TextEdit::multiline(&mut self.intruder_wordlist)
                        .desired_rows(14)
                        .desired_width(f32::INFINITY)
                        .code_editor(),
                );

                cols[1].strong("Hasil Fuzzing:");
                egui::ScrollArea::vertical()
                    .max_height(320.0)
                    .show(&mut cols[1], |ui| {
                        egui::Grid::new("intruder_grid")
                            .striped(true)
                            .min_col_width(75.0)
                            .show(ui, |ui| {
                                ui.strong("Payload");
                                ui.strong("Status");
                                ui.strong("Length (B)");
                                ui.strong("Time (ms)");
                                ui.strong("Flag");
                                ui.end_row();

                                for r in &self.intruder_rows {
                                    ui.label(&r.payload);
                                    ui.label(r.status_code.to_string());
                                    ui.label(r.response_len.to_string());
                                    ui.label(r.elapsed_ms.to_string());
                                    if r.is_anomaly {
                                        ui.strong("⚠️ ANOMALY");
                                    } else {
                                        ui.label("Normal");
                                    }
                                    ui.end_row();
                                }
                            });
                    });
            });
        }
    }

    fn render_metasploit_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("LHOST (IP Lokal/VPN):");
            ui.add(egui::TextEdit::singleline(&mut self.msf_lhost).desired_width(150.0));
            ui.checkbox(
                &mut self.msf_run_searchsploit,
                "Query SearchSploit CLI (Windows/WSL)",
            );

            if ui.button("🔄 Generate dari Hasil Nmap Recon").clicked() {
                if let Some(rep) = &self.recon_report {
                    self.msf_report = Some(build_exploit_bridge(
                        rep,
                        &self.msf_lhost,
                        self.msf_run_searchsploit,
                    ));
                    self.status_msg = "Metasploit Resource Script (.rc) berhasil dibuat.".into();
                } else {
                    self.status_msg =
                        "Jalankan pemindaian pada Tab 1 (Nmap Recon) terlebih dahulu.".into();
                }
            }

            if let Some(msf) = &self.msf_report {
                if ui.button("💾 Simpan Script .rc").clicked() {
                    match save_msf_rc_file(&msf.generated_rc_script) {
                        Ok(p) => {
                            self.status_msg = format!(
                                "Tersimpan: {} (Jalankan: msfconsole -r {})",
                                p.display(),
                                p.display()
                            );
                        }
                        Err(e) => self.status_msg = format!("Gagal simpan .rc: {}", e),
                    }
                }
            }
        });

        ui.add_space(6.0);
        if let Some(msf) = &self.msf_report {
            ui.columns(2, |cols| {
                cols[0].strong("Modul Metasploit & Non-Destructive Check:");
                egui::ScrollArea::vertical()
                    .max_height(350.0)
                    .show(&mut cols[0], |ui| {
                        for rec in &msf.recommendations {
                            ui.group(|ui| {
                                ui.strong(format!("Port {}/tcp — {}", rec.port, rec.msf_module));
                                ui.label(rec.description.clone());
                                ui.label(format!(
                                    "SHA-256 Proof: {}...",
                                    &rec.proof.evidence_sha256[..20]
                                ));
                            });
                            ui.add_space(4.0);
                        }
                        ui.separator();
                        ui.strong("SearchSploit Output:");
                        ui.label(&msf.searchsploit_output);
                    });

                cols[1].strong("Metasploit Resource Script (.rc) Siap Jalankan:");
                let mut rc_txt = msf.generated_rc_script.clone();
                cols[1].add(
                    egui::TextEdit::multiline(&mut rc_txt)
                        .desired_rows(19)
                        .desired_width(f32::INFINITY)
                        .code_editor(),
                );
            });
        } else {
            ui.label("Jalankan Nmap Recon di Tab 1 terlebih dahulu, lalu klik 'Generate dari Hasil Nmap Recon' untuk memetakan modul Metasploit dan SearchSploit.");
        }
    }

    fn render_sniffer_tab(&mut self, ui: &mut egui::Ui) {
        let is_running = self
            .sniffer_ctrl
            .is_running
            .load(std::sync::atomic::Ordering::SeqCst);

        if is_running {
            if let Ok(active_up) = self.sniffer_ctrl.active_upstream.lock() {
                if !active_up.is_empty() && *active_up != self.sniffer_upstream {
                    self.sniffer_upstream = active_up.clone();
                }
            }
        }

        ui.horizontal(|ui| {
            ui.label("Listener:");
            ui.add(egui::TextEdit::singleline(&mut self.sniffer_bind).desired_width(130.0));
            ui.label("Target Link (Gateway):");
            let resp_edit = ui.add(
                egui::TextEdit::singleline(&mut self.sniffer_upstream)
                    .hint_text("Kosongkan untuk mode /https://link-apa-saja.com")
                    .desired_width(270.0),
            );
            if resp_edit.changed() && is_running {
                self.sniffer_ctrl.set_upstream(&self.sniffer_upstream);
            }

            if !is_running {
                if ui.button("▶️ Start Sniffer").clicked() {
                    match self
                        .sniffer_ctrl
                        .start(self.sniffer_bind.clone(), self.sniffer_upstream.clone())
                    {
                        Ok(_) => {
                            self.status_msg = format!(
                                "Sniffer aktif di http://{} — Buka http://{}/https://<link-target> di browser!",
                                self.sniffer_bind, self.sniffer_bind
                            );
                        }
                        Err(e) => self.status_msg = format!("Error Sniffer: {}", e),
                    }
                }
            } else if ui.button("⏹️ Stop Sniffer").clicked() {
                self.sniffer_ctrl.stop();
                self.status_msg = "Sniffer dihentikan.".into();
            }

            if ui.button("🗑️ Bersihkan Log").clicked() {
                self.sniffer_ctrl.clear();
                self.selected_packet_idx = None;
            }
        });

        ui.label(format!(
            "💡 Cara Cepat Gate Link Apa Saja: Buka di browser -> http://{}/https://domain-target-anda.com/login",
            self.sniffer_bind
        ));

        ui.add_space(6.0);
        let packets = self
            .sniffer_ctrl
            .captured
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();

        ui.columns(2, |cols| {
            cols[0].strong(format!("Lalu Lintas Tertangkap ({} paket):", packets.len()));
            egui::ScrollArea::vertical()
                .max_height(335.0)
                .show(&mut cols[0], |ui| {
                    for (idx, pkt) in packets.iter().enumerate() {
                        let jwt_tag = if pkt.extracted_jwt.is_some() {
                            " [JWT!]"
                        } else {
                            ""
                        };
                        let label = format!(
                            "#{} [{}] {} {}{}",
                            pkt.id, pkt.response_status, pkt.method, pkt.target_url, jwt_tag
                        );
                        if ui
                            .selectable_label(self.selected_packet_idx == Some(idx), label)
                            .clicked()
                        {
                            self.selected_packet_idx = Some(idx);
                        }
                    }
                });

            cols[1].strong("Inspeksi Provenance & SHA-256 Forensic Proof:");
            if let Some(sel_idx) = self.selected_packet_idx {
                if let Some(pkt) = packets.get(sel_idx) {
                    egui::ScrollArea::vertical()
                        .max_height(335.0)
                        .show(&mut cols[1], |ui| {
                            ui.label(format!("Client Origin : {}", pkt.client_addr));
                            ui.label(format!(
                                "UTC Timestamp : {}",
                                pkt.proof.capture_timestamp_utc
                            ));
                            ui.label(format!("SHA-256 Hash  : {}", pkt.proof.evidence_sha256));

                            if let Some(jwt_token) = &pkt.extracted_jwt {
                                ui.add_space(4.0);
                                if ui
                                    .button("🔑 Kirim Token JWT Ini ke JWT Inspector ➡")
                                    .clicked()
                                {
                                    self.dec_mode = "JWT Inspector".to_string();
                                    self.dec_input = jwt_token.clone();
                                    self.dec_output = transform_text("JWT Inspector", jwt_token);
                                    self.active_tab = 9;
                                }
                            }

                            ui.separator();
                            if pkt.provenance_findings.is_empty() {
                                ui.label(
                                    "Tidak ada token JWT/kredensial cleartext pada paket ini.",
                                );
                            } else {
                                for pf in &pkt.provenance_findings {
                                    ui.strong(format!("🔑 {}", pf));
                                }
                            }
                            ui.separator();
                            let mut raw_view = format!(
                                "=== RAW REQUEST ===\n{}\n\n=== RAW RESPONSE ===\n{}",
                                pkt.raw_request_preview, pkt.raw_response_preview
                            );
                            ui.add(
                                egui::TextEdit::multiline(&mut raw_view)
                                    .desired_rows(12)
                                    .desired_width(f32::INFINITY)
                                    .code_editor(),
                            );
                        });
                }
            }
        });
    }

    fn render_netcat_decoder_tab(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |cols| {
            cols[0].strong("🔌 Netcat Raw TCP Socket Console");
            cols[0].horizontal(|ui| {
                ui.label("Host:");
                ui.add(egui::TextEdit::singleline(&mut self.nc_host).desired_width(140.0));
                ui.label("Port:");
                ui.add(egui::TextEdit::singleline(&mut self.nc_port).desired_width(60.0));
                ui.checkbox(&mut self.nc_crlf, "\\r\\n");
                if ui.button("⚡ Send").clicked() {
                    if let Ok(port_num) = self.nc_port.trim().parse::<u16>() {
                        match execute_raw_tcp_session(
                            &self.nc_host,
                            port_num,
                            &self.nc_payload,
                            self.nc_crlf,
                        ) {
                            Ok(res) => {
                                self.status_msg = format!(
                                    "Netcat: {} ({} bytes, {} ms)",
                                    res.connected_addr, res.bytes_received, res.elapsed_ms
                                );
                                self.nc_result = Some(res);
                            }
                            Err(e) => self.status_msg = format!("Netcat Error: {}", e),
                        }
                    }
                }
            });
            cols[0].add(
                egui::TextEdit::multiline(&mut self.nc_payload)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .code_editor(),
            );
            if let Some(res) = &self.nc_result {
                let mut out = format!("{}\n\n--- HEX DUMP ---\n{}", res.ascii_output, res.hex_dump);
                cols[0].add(
                    egui::TextEdit::multiline(&mut out)
                        .desired_rows(12)
                        .desired_width(f32::INFINITY)
                        .code_editor(),
                );
            }

            cols[1].strong("🔐 JWT Inspector & Payload Decoder");
            cols[1].horizontal(|ui| {
                egui::ComboBox::from_id_salt("dec_mode_box")
                    .selected_text(&self.dec_mode)
                    .show_ui(ui, |ui| {
                        for mode in [
                            "JWT Inspector",
                            "Base64 Encode",
                            "Base64 Decode",
                            "URL Encode",
                            "URL Decode",
                        ] {
                            ui.selectable_value(&mut self.dec_mode, mode.to_string(), mode);
                        }
                    });
                if ui.button("🔄 Proses").clicked() {
                    self.dec_output = transform_text(&self.dec_mode, &self.dec_input);
                }
            });
            cols[1].add(
                egui::TextEdit::multiline(&mut self.dec_input)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .code_editor(),
            );
            cols[1].add(
                egui::TextEdit::multiline(&mut self.dec_output)
                    .desired_rows(11)
                    .desired_width(f32::INFINITY)
                    .code_editor(),
            );
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1040.0, 660.0]),
        ..Default::default()
    };
    eframe::run_native(
        "WebSec-Suite v3.0 — Forensic-Grade Full-Stack Security & Recon Suite",
        options,
        Box::new(|_cc| Ok(Box::new(WebSecApp::default()))),
    )
}
