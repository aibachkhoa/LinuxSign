//! Chẩn đoán: dịch vụ smart card, thiết bị USB đang cắm, driver và token.

use crate::config::Config;
use crate::manager::{scan, ModuleStatus};
use crate::registry::USB_VENDORS;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct UsbDevice {
    pub id: String,
    pub product: String,
    pub vendor_hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub version: &'static str,
    pub os: String,
    /// None: không áp dụng (Windows/macOS có dịch vụ smart card sẵn).
    pub pcscd_running: Option<bool>,
    pub usb_devices: Vec<UsbDevice>,
    pub modules: Vec<ModuleStatus>,
    pub token_count: usize,
    pub certificate_count: usize,
    /// Gợi ý khắc phục, theo thứ tự nên làm.
    pub advice: Vec<String>,
}

fn pcscd_running() -> Option<bool> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    Some(["/run/pcscd/pcscd.comm", "/var/run/pcscd/pcscd.comm"].iter().any(|p| Path::new(p).exists()))
}

/// Liệt kê thiết bị smart card (lớp CCID 0x0B) hoặc của hãng token đã biết, qua /sys (Linux).
pub fn usb_devices() -> Vec<UsbDevice> {
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir("/sys/bus/usb/devices") else { return out };
    for e in rd.flatten() {
        let d = e.path();
        let read = |f: &str| std::fs::read_to_string(d.join(f)).map(|s| s.trim().to_string()).ok();
        let (Some(vid), Some(pid)) = (read("idVendor"), read("idProduct")) else { continue };
        let name = e.file_name().to_string_lossy().to_string();
        let ccid = std::fs::read_dir(&d)
            .map(|it| {
                it.flatten().any(|i| {
                    i.file_name().to_string_lossy().starts_with(&format!("{name}:"))
                        && std::fs::read_to_string(i.path().join("bInterfaceClass")).map(|c| c.trim() == "0b").unwrap_or(false)
                })
            })
            .unwrap_or(false);
        let known = USB_VENDORS.iter().find(|(v, _)| *v == vid).map(|(_, n)| n.to_string());
        if ccid || known.is_some() {
            out.push(UsbDevice {
                id: format!("{vid}:{pid}"),
                product: read("product").unwrap_or_default(),
                vendor_hint: known.unwrap_or_else(|| "Smart card (CCID)".into()),
            });
        }
    }
    out
}

pub fn run(cfg: &Config, deep: bool) -> DoctorReport {
    let report = scan(cfg, deep);
    let pcscd = pcscd_running();
    let usb = usb_devices();
    let mut advice = vec![];
    if pcscd == Some(false) {
        advice.push("Cài và bật dịch vụ smart card: sudo apt install pcscd libccid && sudo systemctl enable --now pcscd.socket".into());
    }
    if cfg!(target_os = "linux") && usb.is_empty() {
        advice.push("Không thấy USB Token nào: hãy cắm token (thử cổng USB khác nếu đã cắm).".into());
    }
    if report.modules.is_empty() {
        advice.push("Chưa có driver PKCS#11 nào: cài driver Linux của nhà cung cấp CA, hoặc driver mở OpenSC (sudo apt install opensc).".into());
    } else if report.tokens.is_empty() && !usb.is_empty() {
        advice.push("Có token và driver nhưng chưa đọc được chứng thư: driver hiện có có thể không hỗ trợ chip này. Cài driver chính hãng của CA rồi bấm Làm mới.".into());
    }
    for m in report.modules.iter().filter(|m| m.error.is_some()) {
        advice.push(format!("Driver {} lỗi: {}", m.candidate.path, m.error.as_deref().unwrap_or_default()));
    }
    let now = chrono::Utc::now().timestamp();
    for t in &report.tokens {
        if t.pin_locked {
            advice.push(format!("Token \"{}\" đã bị khóa PIN: liên hệ nhà cung cấp CA để mở khóa.", t.label));
        } else if t.pin_final_try {
            advice.push(format!("Token \"{}\" chỉ còn 1 lần nhập PIN: nhập sai nữa sẽ bị khóa.", t.label));
        }
        for c in &t.certificates {
            if c.not_after_ts < now {
                advice.push(format!("Chứng thư \"{}\" đã hết hạn: liên hệ {} để gia hạn.", c.subject_cn, c.issuer_o.as_deref().unwrap_or(&c.issuer_cn)));
            } else if c.days_left <= cfg.expiry_warn_days {
                advice.push(format!("Chứng thư \"{}\" còn {} ngày: nên gia hạn sớm.", c.subject_cn, c.days_left));
            }
        }
    }
    DoctorReport {
        version: crate::VERSION,
        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        pcscd_running: pcscd,
        usb_devices: usb,
        token_count: report.tokens.len(),
        certificate_count: report.tokens.iter().map(|t| t.certificates.len()).sum(),
        modules: report.modules,
        advice,
    }
}
