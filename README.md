# WebSec-Suite v1.0

**Forensic-Grade Full-Stack Security & Recon Suite** built natively in Rust using `eframe` / `egui`. Designed for authorized security auditing, educational lab exercises, and defensive analysis of modern web applications.

---

## Core Modules

1. **Nmap Recon** — Host discovery, port scanning, and service fingerprinting.
2. **Origin IP Unmasker** — Resolves underlying origin infrastructure behind CDN/edge layers.
3. **WAF / IDS / IPS Probe** — Evaluates edge filtering behavior and response anomalies.
4. **Subdomains** — Enumerates active subdomains for authorized asset inventory.
5. **SQLi Auditor** — Differential parameter inspection for SQL injection resilience.
6. **Web Scanner** — Automated security header inspection, technology fingerprinting, and differential active auditing.
7. **Repeater / Intruder** — Manual HTTP request crafting and wordlist-driven parameter/path fuzzing (`§FUZZ§`).
8. **Metasploit / Exploit Bridge** — Local exploit reference and verification workflow integration.
9. **Sniffer & Token** — Real-time HTTP traffic capture and session token inspection.
10. **Netcat & JWT** — Raw TCP socket console, Base64 encoder/decoder, and JWT header/payload/signature analyzer.

---

## Prerequisites & Build

* **Rust Toolchain** (stable, `cargo` & `rustc` 1.75+)
* **Optional External CLI Tools**: `nmap` (for Module 1 host/port reconnaissance

## Legal Warning & Liability Disclaimer

> [!WARNING]
> **Authorized Use Only** — This tool is strictly intended for educational purposes, local lab experimentation, and authorized security assessments.

* **Permitted Scope:** Use this suite solely within controlled environments (such as local VMs, DVWA, or PortSwigger Web Security Academy) or on systems where you hold **explicit prior written authorization** from the asset owner.
* **Prohibited Activities:** Running active scans, fuzzing, packet sniffing, or exploitation modules against public, corporate, educational, or third-party infrastructure without permission is strictly prohibited and may violate applicable cybercrime and data protection laws (including Indonesia's UU ITE and UU PDP).
* **Limitation of Liability:** The author and contributors assume **no responsibility or liability** for any misuse, unauthorized access, service disruption, or legal consequences resulting from the use of this software. Users bear full legal and ethical responsibility for their actions.
  
```bash
git clone [https://github.com/rabiatul0308/websec-suite.git](https://github.com/rabiatul0308/websec-suite.git)
cd websec-suite
cargo build --release
cargo run --release
