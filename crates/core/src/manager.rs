//! Gộp kết quả thăm dò của mọi driver thành danh sách token/chứng thư thống nhất.
//!
//! Một token có thể được nhiều driver cùng thấy (driver hãng và OpenSC). Gộp theo
//! (hãng, model, serial, nhãn): driver ưu tiên cao nhất làm chính, còn lại dự phòng.

use crate::certinfo::CertInfo;
use crate::config::Config;
use crate::discovery::{discover, Candidate};
use crate::probe::{probe_isolated, LibraryInfo};
use rayon::prelude::*;
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::time::Duration;

pub const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Serialize)]
pub struct ModuleRoute {
    pub module: String,
    pub slot_id: u64,
    pub priority: i32,
    pub vendor: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenInfo {
    pub token_id: String,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub login_required: bool,
    pub protected_auth_path: bool,
    pub pin_locked: bool,
    pub pin_final_try: bool,
    pub pin_count_low: bool,
    pub min_pin_len: usize,
    pub max_pin_len: usize,
    pub mechanisms: Vec<String>,
    /// Driver chính trước, dự phòng sau.
    pub routes: Vec<ModuleRoute>,
    /// Chứng thư người dùng (có thể ký).
    pub certificates: Vec<CertInfo>,
    /// Chứng thư CA trung gian/gốc lưu trên token, dùng để dựng chuỗi chứng thư.
    pub ca_certificates: Vec<CertInfo>,
}

impl TokenInfo {
    fn key(&self) -> String {
        format!("{}|{}|{}|{}", self.manufacturer, self.model, self.serial, self.label)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleStatus {
    #[serde(flatten)]
    pub candidate: Candidate,
    pub library: Option<LibraryInfo>,
    pub token_count: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Report {
    pub tokens: Vec<TokenInfo>,
    pub modules: Vec<ModuleStatus>,
}

/// Quét toàn bộ: tìm driver rồi thăm dò song song.
pub fn scan(cfg: &Config, deep: bool) -> Report {
    scan_candidates(discover(cfg, deep))
}

/// Thăm dò một danh sách driver đã biết (ứng dụng desktop dùng để làm mới nhanh
/// khi người dùng cắm/rút token, không cần quét lại đĩa).
pub fn scan_candidates(candidates: Vec<Candidate>) -> Report {
    let results: Vec<_> = candidates.par_iter().map(|c| probe_isolated(c, PROBE_TIMEOUT)).collect();

    let mut tokens: Vec<TokenInfo> = vec![];
    let mut modules = vec![];
    for (c, r) in candidates.into_iter().zip(results) {
        modules.push(ModuleStatus {
            library: r.library.clone(),
            token_count: r.tokens.len(),
            error: r.error.clone(),
            candidate: c.clone(),
        });
        for t in r.tokens {
            if t.error.is_some() && t.label.is_empty() {
                continue;
            }
            let route = ModuleRoute { module: c.path.clone(), slot_id: t.slot_id, priority: c.priority, vendor: c.vendor.clone() };
            let (cas, certs): (Vec<_>, Vec<_>) = t.certificates.into_iter().partition(|ci| ci.is_ca);
            let info = TokenInfo {
                token_id: String::new(),
                label: t.label,
                manufacturer: t.manufacturer,
                model: t.model,
                serial: t.serial,
                login_required: t.login_required,
                protected_auth_path: t.protected_auth_path,
                pin_locked: t.pin_locked,
                pin_final_try: t.pin_final_try,
                pin_count_low: t.pin_count_low,
                min_pin_len: t.min_pin_len,
                max_pin_len: t.max_pin_len,
                mechanisms: t.mechanisms,
                routes: vec![route],
                certificates: certs,
                ca_certificates: cas,
            };
            match tokens.iter_mut().find(|x| x.key() == info.key()) {
                None => tokens.push(info),
                Some(ex) => {
                    let better = info.routes[0].priority > ex.routes[0].priority;
                    ex.routes.extend(info.routes);
                    ex.routes.sort_by(|a, b| b.priority.cmp(&a.priority));
                    if better && !info.mechanisms.is_empty() {
                        ex.mechanisms = info.mechanisms;
                    }
                    for c in info.certificates {
                        if !ex.certificates.iter().any(|x| x.cert_id == c.cert_id) {
                            ex.certificates.push(c);
                        }
                    }
                    for c in info.ca_certificates {
                        if !ex.ca_certificates.iter().any(|x| x.cert_id == c.cert_id) {
                            ex.ca_certificates.push(c);
                        }
                    }
                }
            }
        }
    }
    for t in &mut tokens {
        t.token_id = hex::encode(&Sha1::digest(t.key().as_bytes())[..6]);
        t.certificates.sort_by_key(|c| -c.not_after_ts);
    }
    tokens.retain(|t| !t.certificates.is_empty());
    Report { tokens, modules }
}

#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    #[error("Không tìm thấy chứng thư phù hợp. Token đã cắm và đã cài driver chưa? Thử lệnh `doctor`.")]
    NotFound,
    #[error("Có nhiều chứng thư phù hợp, hãy chọn cụ thể: {0}")]
    Ambiguous(String),
}

/// Tìm chứng thư theo cert_id (hoặc tiền tố), serial, MST, hoặc một phần tên CN.
/// `wanted = None`: nếu cả máy chỉ có đúng một chứng thư còn hạn ký được thì dùng luôn.
pub fn find_certificate<'a>(r: &'a Report, wanted: Option<&str>) -> Result<(&'a TokenInfo, &'a CertInfo), LookupError> {
    let now = chrono::Utc::now().timestamp();
    let mut m = vec![];
    for t in &r.tokens {
        for c in &t.certificates {
            let ok = match wanted {
                None => c.can_sign && c.not_after_ts > now,
                Some(w) => {
                    let w = w.to_lowercase();
                    c.cert_id.starts_with(&w)
                        || c.serial_hex.eq_ignore_ascii_case(&w)
                        || c.tax_code.as_deref().is_some_and(|t| t == w)
                        || c.subject_cn.to_lowercase().contains(&w)
                }
            };
            if ok {
                m.push((t, c));
            }
        }
    }
    match m.len() {
        0 => Err(LookupError::NotFound),
        1 => Ok(m[0]),
        _ => Err(LookupError::Ambiguous(
            m.iter().map(|(_, c)| format!("{} ({})", &c.cert_id[..10], c.subject_cn)).collect::<Vec<_>>().join(", "),
        )),
    }
}
