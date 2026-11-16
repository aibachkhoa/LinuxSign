//! Đọc thông tin chứng thư X.509, kèm các trường đặc thù của chứng thư Việt Nam
//! (MST, CCCD/CMND trong thuộc tính UID) và tính hạn sử dụng.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use x509_parser::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    /// SHA-1 thumbprint (giống Windows cert store); ID ổn định giữa các driver.
    pub cert_id: String,
    pub der_b64: String,
    pub subject: String,
    pub subject_cn: String,
    pub subject_o: Option<String>,
    /// Các trường của Subject theo thứ tự: [("CN", "..."), ("UID", "MST:..."), ...]
    pub subject_fields: Vec<(String, String)>,
    pub issuer_cn: String,
    pub issuer_o: Option<String>,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub not_after_ts: i64,
    pub days_left: i64,
    pub key_type: String,
    pub key_size: Option<usize>,
    pub is_ca: bool,
    pub can_sign: bool,
    /// Mã số thuế (doanh nghiệp/cá nhân), nếu có.
    pub tax_code: Option<String>,
    /// CCCD / CMND / Hộ chiếu, nếu có.
    pub personal_id: Option<String>,
    pub email: Option<String>,
    /// CKA_ID của đối tượng trên token (hex) và nhãn.
    pub cka_id: String,
    pub label: String,
}

impl CertInfo {
    pub fn der(&self) -> Vec<u8> {
        B64.decode(&self.der_b64).unwrap_or_default()
    }

    /// valid | expiring | expired | not_yet_valid
    pub fn status(&self, warn_days: i64) -> &'static str {
        let now = chrono::Utc::now().timestamp();
        if self.not_after_ts < now {
            "expired"
        } else if chrono::DateTime::parse_from_rfc3339(&self.not_before).map(|t| t.timestamp() > now).unwrap_or(false) {
            "not_yet_valid"
        } else if self.days_left <= warn_days {
            "expiring"
        } else {
            "valid"
        }
    }
}

fn short_name(oid: &str) -> &str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.6" => "C",
        "2.5.4.12" => "T",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.9" => "STREET",
        "1.2.840.113549.1.9.1" => "E",
        "0.9.2342.19200300.100.1.1" => "UID",
        other => other,
    }
}

fn name_fields(name: &X509Name) -> Vec<(String, String)> {
    name.iter_attributes()
        .map(|a| {
            let oid = a.attr_type().to_id_string();
            let val = a
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|_| String::from_utf8_lossy(a.attr_value().data).to_string());
            (short_name(&oid).to_string(), val)
        })
        .collect()
}

fn first(fields: &[(String, String)], key: &str) -> Option<String> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

/// Tách MST / CCCD từ các trường UID kiểu "MST:0101234567", "CCCD:0010...", "CMND:...".
fn vn_identifiers(fields: &[(String, String)]) -> (Option<String>, Option<String>) {
    let (mut tax, mut pid) = (None, None);
    for (k, v) in fields.iter().filter(|(k, _)| k == "UID" || k == "SERIALNUMBER") {
        let (prefix, value) = v.split_once(':').unwrap_or(("", v.as_str()));
        match prefix.trim().to_ascii_uppercase().as_str() {
            "MST" | "MNS" | "TIN" => tax = Some(value.trim().to_string()),
            "CCCD" | "CMND" | "HC" | "PASSPORT" | "CMT" => pid = Some(format!("{}: {}", prefix.trim(), value.trim())),
            _ if k == "UID" && tax.is_none() && value.chars().all(|c| c.is_ascii_digit() || c == '-') => {
                tax = Some(value.to_string())
            }
            _ => {}
        }
    }
    (tax, pid)
}

pub fn thumbprint(der: &[u8]) -> String {
    hex::encode(Sha1::digest(der))
}

pub fn parse(der: &[u8], cka_id: &[u8], label: &str) -> anyhow::Result<CertInfo> {
    let (_, c) = parse_x509_certificate(der).map_err(|e| anyhow::anyhow!("Chứng thư lỗi: {e}"))?;
    let subj = name_fields(c.subject());
    let iss = name_fields(c.issuer());
    let nb = c.validity().not_before.timestamp();
    let na = c.validity().not_after.timestamp();
    let now = chrono::Utc::now().timestamp();
    let ts = |t: i64| chrono::DateTime::from_timestamp(t, 0).map(|d| d.to_rfc3339()).unwrap_or_default();

    let (key_type, key_size) = match c.public_key().parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(r)) => ("RSA".to_string(), Some(r.key_size())),
        Ok(x509_parser::public_key::PublicKey::EC(p)) => ("EC".to_string(), Some(p.key_size())),
        _ => (c.public_key().algorithm.algorithm.to_id_string(), None),
    };
    let is_ca = c.basic_constraints().ok().flatten().map(|b| b.value.ca).unwrap_or(false);
    let can_sign = c
        .key_usage()
        .ok()
        .flatten()
        .map(|k| k.value.digital_signature() || k.value.non_repudiation())
        .unwrap_or(true);
    let (tax_code, personal_id) = vn_identifiers(&subj);

    Ok(CertInfo {
        cert_id: thumbprint(der),
        der_b64: B64.encode(der),
        subject: c.subject().to_string(),
        subject_cn: first(&subj, "CN").unwrap_or_else(|| c.subject().to_string()),
        subject_o: first(&subj, "O"),
        issuer_cn: first(&iss, "CN").unwrap_or_else(|| c.issuer().to_string()),
        issuer_o: first(&iss, "O"),
        serial_hex: hex::encode(c.tbs_certificate.raw_serial()),
        not_before: ts(nb),
        not_after: ts(na),
        not_after_ts: na,
        days_left: (na - now).div_euclid(86_400),
        key_type,
        key_size,
        is_ca,
        can_sign,
        tax_code,
        personal_id,
        email: first(&subj, "E"),
        cka_id: hex::encode(cka_id),
        label: label.to_string(),
        subject_fields: subj,
    })
}

/// Các phần thô của chứng thư cần cho CMS: issuer Name (DER), serial (nội dung INTEGER), SPKI (DER).
pub struct CertParts {
    pub issuer_der: Vec<u8>,
    pub serial: Vec<u8>,
    pub spki_der: Vec<u8>,
}

pub fn parts(der: &[u8]) -> anyhow::Result<CertParts> {
    let (_, c) = parse_x509_certificate(der).map_err(|e| anyhow::anyhow!("Chứng thư lỗi: {e}"))?;
    Ok(CertParts {
        issuer_der: c.issuer().as_raw().to_vec(),
        serial: c.tbs_certificate.raw_serial().to_vec(),
        spki_der: c.public_key().raw.to_vec(),
    })
}
