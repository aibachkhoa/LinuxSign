//! Thăm dò MỘT thư viện PKCS#11, luôn chạy trong tiến trình con riêng.
//!
//! Driver của hãng là mã đóng, có thể segfault, treo, hoặc xung đột với driver
//! hãng khác khi nạp chung tiến trình. Mỗi module được thăm dò bằng cách chạy lại
//! chính file thực thi hiện tại với tham số ẩn `__linuxsign_probe <module>`, có
//! timeout. Không đăng nhập, không cần PIN: chỉ đọc thông tin công khai.

use crate::certinfo::{self, CertInfo};
use crate::discovery::Candidate;
use crate::PROBE_ARG;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LibraryInfo {
    pub manufacturer: String,
    pub description: String,
    pub version: String,
    pub cryptoki: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProbedToken {
    pub slot_id: u64,
    pub slot_description: String,
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
    pub certificates: Vec<CertInfo>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProbeResult {
    pub module: String,
    pub library: Option<LibraryInfo>,
    pub tokens: Vec<ProbedToken>,
    pub error: Option<String>,
}

pub fn init_module(path: &str) -> Result<Pkcs11, cryptoki::error::Error> {
    let ctx = Pkcs11::new(path)?;
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::CryptokiAlreadyInitialized, _)) => Ok(ctx),
        Err(e) => Err(e),
    }
}

/// Thăm dò trong tiến trình hiện tại. CHỈ gọi từ tiến trình con.
pub fn probe_in_process(path: &str) -> ProbeResult {
    let mut res = ProbeResult { module: path.into(), ..Default::default() };
    let ctx = match init_module(path) {
        Ok(c) => c,
        Err(e) => {
            res.error = Some(format!("Không nạp được driver: {e}"));
            return res;
        }
    };
    if let Ok(li) = ctx.get_library_info() {
        res.library = Some(LibraryInfo {
            manufacturer: li.manufacturer_id().trim().into(),
            description: li.library_description().trim().into(),
            version: li.library_version().to_string(),
            cryptoki: li.cryptoki_version().to_string(),
        });
    }
    let slots = match ctx.get_slots_with_token() {
        Ok(s) => s,
        Err(e) => {
            res.error = Some(format!("Không liệt kê được khe đọc: {e}"));
            return res;
        }
    };
    for slot in slots {
        let mut t = ProbedToken { slot_id: slot.id(), ..Default::default() };
        if let Ok(si) = ctx.get_slot_info(slot) {
            t.slot_description = si.slot_description().trim().into();
        }
        match ctx.get_token_info(slot) {
            Ok(ti) => {
                t.label = ti.label().trim().into();
                t.manufacturer = ti.manufacturer_id().trim().into();
                t.model = ti.model().trim().into();
                t.serial = ti.serial_number().trim().into();
                t.login_required = ti.login_required();
                t.protected_auth_path = ti.protected_authentication_path();
                t.pin_locked = ti.user_pin_locked();
                t.pin_final_try = ti.user_pin_final_try();
                t.pin_count_low = ti.user_pin_count_low();
                t.min_pin_len = ti.min_pin_length();
                t.max_pin_len = ti.max_pin_length();
            }
            Err(e) => {
                t.error = Some(e.to_string());
                res.tokens.push(t);
                continue;
            }
        }
        t.mechanisms = ctx
            .get_mechanism_list(slot)
            .map(|v| v.iter().map(|m| m.to_string()).collect())
            .unwrap_or_default();
        t.mechanisms.sort();
        match ctx.open_ro_session(slot) {
            Ok(session) => {
                let tmpl = [
                    Attribute::Class(ObjectClass::CERTIFICATE),
                    Attribute::CertificateType(CertificateType::X_509),
                ];
                for obj in session.find_objects(&tmpl).unwrap_or_default() {
                    let Ok(attrs) = session.get_attributes(
                        obj,
                        &[AttributeType::Value, AttributeType::Id, AttributeType::Label],
                    ) else {
                        continue;
                    };
                    let (mut der, mut id, mut label) = (vec![], vec![], String::new());
                    for a in attrs {
                        match a {
                            Attribute::Value(v) => der = v,
                            Attribute::Id(v) => id = v,
                            Attribute::Label(v) => label = String::from_utf8_lossy(&v).trim().to_string(),
                            _ => {}
                        }
                    }
                    if der.is_empty() {
                        continue;
                    }
                    if let Ok(ci) = certinfo::parse(&der, &id, &label) {
                        t.certificates.push(ci);
                    }
                }
            }
            Err(e) => t.error = Some(format!("Không mở được phiên: {e}")),
        }
        res.tokens.push(t);
    }
    res
}

/// Gọi ở đầu `main()` của mọi binary. Nếu tiến trình được khởi chạy ở chế độ
/// thăm dò thì in JSON ra stdout và thoát luôn.
pub fn maybe_run_probe_mode() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == PROBE_ARG {
        let r = probe_in_process(&args[2]);
        println!("{}", serde_json::to_string(&r).unwrap_or_else(|_| "{}".into()));
        std::process::exit(0);
    }
}

/// Thăm dò một module trong tiến trình con, có timeout.
pub fn probe_isolated(c: &Candidate, timeout: Duration) -> ProbeResult {
    let fail = |msg: String| ProbeResult { module: c.path.clone(), error: Some(msg), ..Default::default() };
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return fail(format!("Không xác định được file thực thi: {e}")),
    };
    let mut child = match Command::new(exe)
        .arg(PROBE_ARG)
        .arg(&c.path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(ch) => ch,
        Err(e) => return fail(format!("Không chạy được tiến trình thăm dò: {e}")),
    };
    // Đọc stdout ở luồng riêng để tiến trình con không bị nghẽn khi output lớn.
    let mut stdout = child.stdout.take().expect("piped");
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(15)),
            Err(_) => break None,
        }
    };
    let out = reader.join().unwrap_or_default();
    match status {
        None => fail(format!("Driver bị treo (quá {}s)", timeout.as_secs())),
        Some(st) => match serde_json::from_str::<ProbeResult>(out.trim()) {
            Ok(r) => r,
            Err(_) if !st.success() => fail(format!("Driver làm crash tiến trình ({st})")),
            Err(e) => fail(format!("Kết quả thăm dò không hợp lệ: {e}")),
        },
    }
}
