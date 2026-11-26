use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

pub struct NetcatResponse {
    pub connected_addr: String,
    pub elapsed_ms: u128,
    pub bytes_received: usize,
    pub ascii_output: String,
    pub hex_dump: String,
}

pub fn execute_raw_tcp_session(
    host: &str,
    port: u16,
    raw_payload: &str,
    append_crlf: bool,
) -> Result<NetcatResponse, String> {
    let target = format!("{}:{}", host.trim(), port);
    let socket_addr = target
        .to_socket_addrs()
        .map_err(|e| format!("Gagal resolve alamat '{}': {}", target, e))?
        .next()
        .ok_or_else(|| "Alamat tujuan tidak valid.".to_string())?;

    let start = Instant::now();
    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5))
        .map_err(|e| format!("Koneksi TCP ke {} ditolak/timeout: {}", socket_addr, e))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(1200)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;

    // Terjemahkan escape sequences seperti \r dan \n
    let mut processed = raw_payload.replace("\\r", "\r").replace("\\n", "\n");
    if append_crlf && !processed.is_empty() && !processed.ends_with("\r\n") {
        processed.push_str("\r\n");
    }

    if !processed.is_empty() {
        stream
            .write_all(processed.as_bytes())
            .map_err(|e| format!("Gagal mengirim payload TCP: {}", e))?;
        let _ = stream.flush();
    }

    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if buffer.len() >= 16384 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let elapsed_ms = start.elapsed().as_millis();
    let ascii_output = if buffer.is_empty() {
        "<Koneksi berhasil tersambung, tetapi server tidak mengirim balasan data>".to_string()
    } else {
        String::from_utf8_lossy(&buffer).to_string()
    };

    let hex_dump = buffer
        .chunks(16)
        .enumerate()
        .map(|(line_idx, bytes)| {
            let hex_part: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
            let ascii_part: String = bytes
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!(
                "{:04X}: {:<48} | {}",
                line_idx * 16,
                hex_part.join(" "),
                ascii_part
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(NetcatResponse {
        connected_addr: socket_addr.to_string(),
        elapsed_ms,
        bytes_received: buffer.len(),
        ascii_output,
        hex_dump,
    })
}
