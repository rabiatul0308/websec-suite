
# WebSec-Suite v1.0

**Forensic-Grade Full-Stack Security & Recon Suite** built natively in Rust using `eframe` / `egui`[cite: 1, 6]. Designed for authorized security auditing, educational lab exercises, and defensive analysis of modern web applications.

---

## Core Modules

1. **Nmap Recon** — Host discovery, port scanning, and service fingerprinting[cite: 1].
2. **Origin IP Unmasker** — Resolves underlying origin infrastructure behind CDN/edge layers[cite: 1].
3. **WAF / IDS / IPS Probe** — Evaluates edge filtering behavior and response anomalies[cite: 1].
4. **Subdomains** — Enumerates active subdomains for authorized asset inventory[cite: 1].
5. **SQLi Auditor** — Differential parameter inspection for SQL injection resilience[cite: 1].
6. **Web Scanner** — Automated security header inspection, technology fingerprinting, and differential active auditing[cite: 1, 5, 9].
7. **Repeater / Intruder** — Manual HTTP request crafting and wordlist-driven parameter/path fuzzing (`§FUZZ§`)[cite: 1].
8. **Metasploit / Exploit Bridge** — Local exploit reference and verification workflow integration[cite: 1, 6].
9. **Sniffer & Token** — Real-time HTTP traffic capture and session token inspection[cite: 1, 6].
10. **Netcat & JWT** — Raw TCP socket console, Base64 encoder/decoder, and JWT header/payload/signature analyzer[cite: 1, 4].

---

## Prerequisites & Build

* **Rust Toolchain** (stable, `cargo` & `rustc` 1.75+)
* **Optional External CLI Tools**: `nmap` (for Module 1 host/port reconnaissance)

```bash
git clone [https://github.com/rabiatul0308/websec-suite.git](https://github.com/rabiatul0308/websec-suite.git)
cd websec-suite
cargo build --release
cargo run --release
