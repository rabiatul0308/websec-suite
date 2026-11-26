use reqwest::blocking::Client;
use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedForm {
    pub action_url: String,
    pub method: String,
    pub inputs: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SqliFinding {
    pub severity: String,
    pub technique: String,
    pub vector_location: String,
    pub parameter_name: String,
    pub payload_used: String,
    pub dbms_hint: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SqliAuditReport {
    pub target_url: String,
    pub forms_discovered: Vec<ExtractedForm>,
    pub findings: Vec<SqliFinding>,
    pub elapsed_ms: u128,
}

const SQL_ERROR_SIGNATURES: &[(&str, &str)] = &[
    ("you have an error in your sql syntax", "MySQL / MariaDB"),
    ("warning: mysql", "MySQL / MariaDB"),
    ("mysqli_sql_exception", "MySQLi (PHP)"),
    ("supplied argument is not a valid mysql", "MySQL / MariaDB"),
    ("postgresql query failed", "PostgreSQL"),
    ("pg_query(): query failed", "PostgreSQL"),
    ("unterminated quoted string at or near", "PostgreSQL"),
    ("syntax error at or near", "PostgreSQL"),
    (
        "unclosed quotation mark after the character string",
        "Microsoft SQL Server",
    ),
    (
        "microsoft ole db provider for sql server",
        "Microsoft SQL Server",
    ),
    ("sqlstate[42000]", "PDO / SQL Syntax Error"),
    ("sqlstate[hy000]", "PDO Database Error"),
    ("sqlite3::sqlexception", "SQLite"),
    ("sqlite_error", "SQLite"),
    ("ora-01756", "Oracle Database"),
    ("ora-00933", "Oracle Database"),
];

pub fn extract_forms_from_url(raw_url: &str) -> Result<Vec<ExtractedForm>, String> {
    let normalized = normalize_url(raw_url);
    let base_url = Url::parse(&normalized).map_err(|e| format!("URL tidak valid: {}", e))?;

    let client = build_sqli_client()?;
    let resp = client
        .get(base_url.clone())
        .send()
        .map_err(|e| format!("Gagal mengambil halaman: {}", e))?;
    let body = resp.text().unwrap_or_default();

    Ok(parse_html_forms(&base_url, &body))
}

pub fn run_sqli_audit(
    raw_url: &str,
    include_forms: bool,
    enable_time_based: bool,
) -> Result<SqliAuditReport, String> {
    let start = Instant::now();
    let normalized = normalize_url(raw_url);
    let base_url = Url::parse(&normalized).map_err(|e| format!("URL tidak valid: {}", e))?;
    let client = build_sqli_client()?;

    let (baseline_body, baseline_ms) = send_get_timed(&client, &base_url)?;
    let forms_discovered = parse_html_forms(&base_url, &baseline_body);
    let mut findings = Vec::new();

    // 1. Uji Parameter URL (GET)
    let query_pairs: Vec<(String, String)> = base_url.query_pairs().into_owned().collect();
    if !query_pairs.is_empty() {
        audit_get_parameters(
            &client,
            &base_url,
            &query_pairs,
            &baseline_body,
            baseline_ms,
            enable_time_based,
            &mut findings,
        );
    }

    // 2. Uji Setiap Form HTML yang Ditemukan (GET / POST)
    if include_forms {
        for form in &forms_discovered {
            if form.inputs.is_empty() {
                continue;
            }
            audit_form_target(&client, form, enable_time_based, &mut findings);
        }
    }

    Ok(SqliAuditReport {
        target_url: base_url.to_string(),
        forms_discovered,
        findings,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

fn audit_get_parameters(
    client: &Client,
    base_url: &Url,
    pairs: &[(String, String)],
    baseline_body: &str,
    baseline_ms: u128,
    enable_time_based: bool,
    findings: &mut Vec<SqliFinding>,
) {
    let error_payloads = ["'", "\"", "')", "\")", "\\"];
    let baseline_lower = baseline_body.to_lowercase();

    for (target_param, orig_val) in pairs {
        let mut found_error = false;

        // A. Error-Based SQLi
        for payload in error_payloads {
            let mut test_url = base_url.clone();
            rebuild_query(
                &mut test_url,
                pairs,
                target_param,
                &format!("{}{}", orig_val, payload),
            );

            if let Ok((resp_body, _)) = send_get_timed(client, &test_url) {
                let resp_lower = resp_body.to_lowercase();
                if let Some((sig, dbms)) = SQL_ERROR_SIGNATURES
                    .iter()
                    .find(|(sig, _)| resp_lower.contains(*sig) && !baseline_lower.contains(*sig))
                {
                    found_error = true;
                    findings.push(SqliFinding {
                        severity: "CRITICAL".into(),
                        technique: "Error-Based SQL Injection".into(),
                        vector_location: format!("GET Query Parameter ({})", base_url.path()),
                        parameter_name: target_param.clone(),
                        payload_used: payload.to_string(),
                        dbms_hint: dbms.to_string(),
                        evidence: format!("Signature error '{}' muncul pada respons (tidak ada di baseline).", sig),
                        remediation: "Gunakan Prepared Statements / Parameterized Queries dan matikan detail error SQL di produksi.".into(),
                    });
                    break;
                }
            }
        }

        // B. Boolean-Based Blind SQLi (TRUE vs FALSE Differential)
        if !found_error {
            let boolean_sets =
                if orig_val.chars().all(|c| c.is_ascii_digit()) && !orig_val.is_empty() {
                    vec![
                        (
                            format!("{} AND 1=1", orig_val),
                            format!("{} AND 1=2", orig_val),
                        ),
                        (
                            format!("{}' OR '1'='1", orig_val),
                            format!("{}' OR '1'='2", orig_val),
                        ),
                    ]
                } else {
                    vec![(
                        format!("{}' OR '1'='1", orig_val),
                        format!("{}' OR '1'='2", orig_val),
                    )]
                };

            for (true_pay, false_pay) in boolean_sets {
                let mut u_true = base_url.clone();
                let mut u_false = base_url.clone();
                rebuild_query(&mut u_true, pairs, target_param, &true_pay);
                rebuild_query(&mut u_false, pairs, target_param, &false_pay);

                if let (Ok((b_true, _)), Ok((b_false, _))) = (
                    send_get_timed(client, &u_true),
                    send_get_timed(client, &u_false),
                ) {
                    let base_len = baseline_body.len();
                    let true_diff = (b_true.len() as isize - base_len as isize).unsigned_abs();
                    let false_diff = (b_false.len() as isize - base_len as isize).unsigned_abs();

                    if true_diff <= 20 && false_diff >= 90 {
                        findings.push(SqliFinding {
                            severity: "CRITICAL".into(),
                            technique: "Boolean-Based Blind SQL Injection".into(),
                            vector_location: format!("GET Query Parameter ({})", base_url.path()),
                            parameter_name: target_param.clone(),
                            payload_used: format!("TRUE: [{}] vs FALSE: [{}]", true_pay, false_pay),
                            dbms_hint: "Generic SQL DBMS".into(),
                            evidence: format!(
                                "Baseline: {} B | TRUE: {} B (identik) | FALSE: {} B (berubah signifikan).",
                                base_len,
                                b_true.len(),
                                b_false.len()
                            ),
                            remediation: "Terapkan Parameterized Queries pada seluruh filter dan klausa WHERE.".into(),
                        });
                        break;
                    }
                }
            }
        }

        // C. Time-Based Blind SQLi (Wajib 2x konfirmasi berturut-turut >= baseline + 3800ms)
        if enable_time_based {
            let time_payloads = [
                ("' AND SLEEP(4)-- -", "MySQL / MariaDB"),
                ("'; SELECT pg_sleep(4)--", "PostgreSQL"),
                ("'; WAITFOR DELAY '0:0:4'--", "Microsoft SQL Server"),
            ];

            for (t_pay, dbms) in time_payloads {
                let mut u_time = base_url.clone();
                rebuild_query(
                    &mut u_time,
                    pairs,
                    target_param,
                    &format!("{}{}", orig_val, t_pay),
                );

                if let Ok((_, d1)) = send_get_timed(client, &u_time) {
                    if d1 >= baseline_ms + 3800 {
                        if let Ok((_, d2)) = send_get_timed(client, &u_time) {
                            if d2 >= baseline_ms + 3800 {
                                findings.push(SqliFinding {
                                    severity: "CRITICAL".into(),
                                    technique: "Time-Based Blind SQL Injection (2x Verified)".into(),
                                    vector_location: format!("GET Query Parameter ({})", base_url.path()),
                                    parameter_name: target_param.clone(),
                                    payload_used: t_pay.to_string(),
                                    dbms_hint: dbms.to_string(),
                                    evidence: format!(
                                        "Baseline: {} ms | Hit #1: {} ms | Hit #2: {} ms (konsisten >= +3800 ms).",
                                        baseline_ms, d1, d2
                                    ),
                                    remediation: "Gunakan Prepared Statements dan batasi execution timeout query database.".into(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn audit_form_target(
    client: &Client,
    form: &ExtractedForm,
    enable_time_based: bool,
    findings: &mut Vec<SqliFinding>,
) {
    let Ok(action_url) = Url::parse(&form.action_url) else {
        return;
    };

    let (base_body, base_ms) =
        match send_form_timed(client, &action_url, &form.method, &form.inputs) {
            Ok(res) => res,
            Err(_) => return,
        };
    let base_lower = base_body.to_lowercase();
    let error_payloads = ["'", "\"", "')", "\\"];

    for (idx, (field_name, orig_val)) in form.inputs.iter().enumerate() {
        let lower_name = field_name.to_lowercase();
        if lower_name.contains("csrf") || lower_name == "_token" {
            continue;
        }

        let mut error_confirmed = false;
        for payload in error_payloads {
            let mut mutated = form.inputs.clone();
            mutated[idx].1 = format!("{}{}", orig_val, payload);

            if let Ok((resp_body, _)) = send_form_timed(client, &action_url, &form.method, &mutated)
            {
                let resp_lower = resp_body.to_lowercase();
                if let Some((sig, dbms)) = SQL_ERROR_SIGNATURES
                    .iter()
                    .find(|(sig, _)| resp_lower.contains(*sig) && !base_lower.contains(*sig))
                {
                    error_confirmed = true;
                    findings.push(SqliFinding {
                        severity: "CRITICAL".into(),
                        technique: "Error-Based SQL Injection (Form)".into(),
                        vector_location: format!("{} Form -> {}", form.method, form.action_url),
                        parameter_name: field_name.clone(),
                        payload_used: payload.to_string(),
                        dbms_hint: dbms.to_string(),
                        evidence: format!(
                            "Signature error SQL '{}' terpicu saat submit form.",
                            sig
                        ),
                        remediation:
                            "Gunakan Parameterized Queries / ORM binding pada handler form backend."
                                .into(),
                    });
                    break;
                }
            }
        }

        if !error_confirmed && enable_time_based {
            let time_payloads = [
                ("' AND SLEEP(4)-- -", "MySQL / MariaDB"),
                ("'; SELECT pg_sleep(4)--", "PostgreSQL"),
                ("'; WAITFOR DELAY '0:0:4'--", "Microsoft SQL Server"),
            ];

            for (t_pay, dbms) in time_payloads {
                let mut mutated = form.inputs.clone();
                mutated[idx].1 = format!("{}{}", orig_val, t_pay);

                if let Ok((_, d1)) = send_form_timed(client, &action_url, &form.method, &mutated) {
                    if d1 >= base_ms + 3800 {
                        if let Ok((_, d2)) =
                            send_form_timed(client, &action_url, &form.method, &mutated)
                        {
                            if d2 >= base_ms + 3800 {
                                findings.push(SqliFinding {
                                    severity: "CRITICAL".into(),
                                    technique: "Time-Based Blind SQL Injection (Form, 2x Verified)"
                                        .into(),
                                    vector_location: format!(
                                        "{} Form -> {}",
                                        form.method, form.action_url
                                    ),
                                    parameter_name: field_name.clone(),
                                    payload_used: t_pay.to_string(),
                                    dbms_hint: dbms.to_string(),
                                    evidence: format!(
                                        "Baseline: {} ms | Hit #1: {} ms | Hit #2: {} ms.",
                                        base_ms, d1, d2
                                    ),
                                    remediation:
                                        "Gunakan Parameterized Queries pada pemrosesan input form."
                                            .into(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn parse_html_forms(base_url: &Url, html: &str) -> Vec<ExtractedForm> {
    let doc = Html::parse_document(html);
    let form_sel = Selector::parse("form").unwrap();
    let input_sel = Selector::parse("input, textarea, select").unwrap();

    let mut forms = Vec::new();
    for form_el in doc.select(&form_sel) {
        let raw_action = form_el.value().attr("action").unwrap_or("");
        let action_url = base_url
            .join(raw_action)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| base_url.to_string());

        let method = form_el
            .value()
            .attr("method")
            .unwrap_or("GET")
            .trim()
            .to_uppercase();

        let mut inputs = Vec::new();
        for inp in form_el.select(&input_sel) {
            if let Some(name) = inp.value().attr("name") {
                let input_type = inp.value().attr("type").unwrap_or("text").to_lowercase();
                if input_type == "submit" || input_type == "button" || input_type == "reset" {
                    continue;
                }
                let default_val = inp
                    .value()
                    .attr("value")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "test1".to_string());
                inputs.push((name.to_string(), default_val));
            }
        }

        forms.push(ExtractedForm {
            action_url,
            method,
            inputs,
        });
    }
    forms
}

fn rebuild_query(url: &mut Url, pairs: &[(String, String)], target_key: &str, new_val: &str) {
    let mut qp = url.query_pairs_mut();
    qp.clear();
    for (k, v) in pairs {
        if k == target_key {
            qp.append_pair(k, new_val);
        } else {
            qp.append_pair(k, v);
        }
    }
}

fn send_get_timed(client: &Client, url: &Url) -> Result<(String, u128), String> {
    let start = Instant::now();
    let resp = client.get(url.clone()).send().map_err(|e| e.to_string())?;
    let body = resp.text().unwrap_or_default();
    Ok((body, start.elapsed().as_millis()))
}

fn send_form_timed(
    client: &Client,
    action_url: &Url,
    method: &str,
    inputs: &[(String, String)],
) -> Result<(String, u128), String> {
    let start = Instant::now();
    let resp = if method == "POST" {
        let mut form_map = HashMap::new();
        for (k, v) in inputs {
            form_map.insert(k.clone(), v.clone());
        }
        client
            .post(action_url.clone())
            .form(&form_map)
            .send()
            .map_err(|e| e.to_string())?
    } else {
        let mut get_url = action_url.clone();
        {
            let mut qp = get_url.query_pairs_mut();
            qp.clear();
            for (k, v) in inputs {
                qp.append_pair(k, v);
            }
        }
        client.get(get_url).send().map_err(|e| e.to_string())?
    };
    let body = resp.text().unwrap_or_default();
    Ok((body, start.elapsed().as_millis()))
}

fn build_sqli_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .user_agent("WebSec-SQLiAuditor/2.0")
        .build()
        .map_err(|e| e.to_string())
}

fn normalize_url(raw: &str) -> String {
    if raw.starts_with("http://") || raw.starts_with("https://") {
        raw.trim().to_string()
    } else {
        format!("https://{}", raw.trim())
    }
}
