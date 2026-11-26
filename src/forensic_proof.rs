use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct ForensicStamp {
    pub capture_timestamp_utc: u64,
    pub evidence_sha256: String,
    pub verification_method: String,
}

impl ForensicStamp {
    pub fn generate(method: &str, request_raw: &str, response_raw: &str) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut hasher = Sha256::new();
        hasher.update(ts.to_le_bytes());
        hasher.update(method.as_bytes());
        hasher.update(b"|REQ|");
        hasher.update(request_raw.as_bytes());
        hasher.update(b"|RES|");
        hasher.update(response_raw.as_bytes());

        let result = hasher.finalize();
        let hex_hash: String = result.iter().map(|b| format!("{:02x}", b)).collect();

        Self {
            capture_timestamp_utc: ts,
            evidence_sha256: hex_hash,
            verification_method: method.to_string(),
        }
    }
}