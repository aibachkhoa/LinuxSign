//! Ứng dụng desktop LinuxSign (Tauri). Giao diện ở app/ui, lõi ở crates/core.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use linuxsign_core::agent::{self, AgentHandle};
use linuxsign_core::cms::{self, CmsOptions};
use linuxsign_core::discovery::{discover, Candidate};
use linuxsign_core::doctor::{self, DoctorReport};
use linuxsign_core::manager::{scan_candidates, Report};
use linuxsign_core::pdf::{self, PdfSignOptions, VisibleSignature};
use linuxsign_core::xml::{self, XmlProfile, XmlSignOptions};
use linuxsign_core::{find_certificate, probe, Config, HashAlg, Signer};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;

mod tray;

#[derive(Default)]
struct AppState {
    /// Danh sách driver đã tìm được; làm mới nhanh chỉ thăm dò lại các driver này.
    candidates: Mutex<Option<Vec<Candidate>>>,
    report: Mutex<Report>,
    agent: Mutex<Option<AgentHandle>>,
    agent_error: Mutex<Option<String>>,
    /// Chứng thư đã thông báo hết hạn → ngày thông báo (mỗi chứng thư tối đa 1 lần/ngày)
    notified: Mutex<std::collections::HashMap<String, chrono::NaiveDate>>,
    /// Đã báo "vẫn chạy ở khay" lần đầu ẩn cửa sổ chưa
    hinted_tray: std::sync::atomic::AtomicBool,
}

type CmdResult<T> = Result<T, String>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> CmdResult<T> + Send + 'static) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

#[derive(Serialize)]
struct ScanResult {
    report: Report,
    warn_days: i64,
    scanned_at: String,
}

fn do_scan(app: &AppHandle, deep: bool) -> ScanResult {
    let st = app.state::<AppState>();
    let cfg = Config::load();
    let cands = {
        let cached = st.candidates.lock().unwrap().clone();
        match cached {
            Some(c) if !deep => c,
            _ => {
                let c = discover(&cfg, deep);
                *st.candidates.lock().unwrap() = Some(c.clone());
                c
            }
        }
    };
    let report = scan_candidates(cands);
    *st.report.lock().unwrap() = report.clone();
    notify_expiry(app, &report, cfg.expiry_warn_days);
    tray::refresh(app, &report, cfg.expiry_warn_days);
    ScanResult { report, warn_days: cfg.expiry_warn_days, scanned_at: chrono::Local::now().format("%H:%M:%S").to_string() }
}

/// Thông báo hệ thống khi chứng thư sắp/đã hết hạn (mỗi chứng thư tối đa 1 lần/ngày,
/// để ứng dụng chạy nền lâu ngày vẫn nhắc lại hằng ngày).
fn notify_expiry(app: &AppHandle, r: &Report, warn_days: i64) {
    let st = app.state::<AppState>();
    let mut seen = st.notified.lock().unwrap();
    let today = chrono::Local::now().date_naive();
    for c in r.tokens.iter().flat_map(|t| &t.certificates) {
        let status = c.status(warn_days);
        if (status == "expiring" || status == "expired") && seen.get(&c.cert_id) != Some(&today) {
            seen.insert(c.cert_id.clone(), today);
            let body = if status == "expired" {
                format!("Chứng thư \"{}\" đã hết hạn từ {}. Liên hệ {} để gia hạn.", c.subject_cn, &c.not_after[..10], c.issuer_o.as_deref().unwrap_or(&c.issuer_cn))
            } else {
                format!("Chứng thư \"{}\" còn {} ngày (hết hạn {}).", c.subject_cn, c.days_left, &c.not_after[..10])
            };
            let _ = app.notification().builder().title("LinuxSign: chứng thư sắp hết hạn").body(body).show();
        }
    }
}

#[tauri::command]
async fn scan_tokens(app: AppHandle, deep: bool) -> CmdResult<ScanResult> {
    blocking(move || Ok(do_scan(&app, deep))).await
}

#[tauri::command]
async fn run_doctor() -> CmdResult<DoctorReport> {
    blocking(|| Ok(doctor::run(&Config::load(), true))).await
}

#[tauri::command]
fn get_config() -> Config {
    Config::load()
}

#[tauri::command]
fn save_config(app: AppHandle, cfg: Config) -> CmdResult<AgentStatus> {
    cfg.save().map_err(|e| format!("Không lưu được cấu hình: {e}"))?;
    *app.state::<AppState>().candidates.lock().unwrap() = None; // driver có thể đã đổi
    apply_agent(&app, &cfg);
    Ok(agent_status(app))
}

#[tauri::command]
fn get_autostart(app: AppHandle) -> bool {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().unwrap_or(false)
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> CmdResult<bool> {
    tray::set_autostart(&app, enabled)?;
    Ok(enabled)
}

#[derive(Serialize)]
struct AgentStatus {
    running: bool,
    port: Option<u16>,
    error: Option<String>,
}

fn apply_agent(app: &AppHandle, cfg: &Config) {
    let st = app.state::<AppState>();
    if let Some(h) = st.agent.lock().unwrap().take() {
        h.stop();
    }
    *st.agent_error.lock().unwrap() = None;
    if cfg.agent_enabled {
        match agent::start(cfg.clone(), cfg.agent_port) {
            Ok(h) => *st.agent.lock().unwrap() = Some(h),
            Err(e) => *st.agent_error.lock().unwrap() = Some(e),
        }
    }
    tray::set_agent_checked(app, st.agent.lock().unwrap().is_some());
}

#[tauri::command]
fn agent_status(app: AppHandle) -> AgentStatus {
    let st = app.state::<AppState>();
    let port = st.agent.lock().unwrap().as_ref().map(|h| h.port);
    let error = st.agent_error.lock().unwrap().clone();
    AgentStatus { running: port.is_some(), port, error }
}

#[tauri::command]
async fn pick_file(app: AppHandle, kind: String) -> CmdResult<Option<String>> {
    blocking(move || {
        let mut d = app.dialog().file();
        if kind == "pdf" {
            d = d.add_filter("PDF", &["pdf", "PDF"]);
        } else if kind == "xml" {
            d = d.add_filter("XML", &["xml", "XML"]);
        } else if kind == "font" {
            d = d.add_filter("Font TrueType/OpenType", &["ttf", "otf", "TTF", "OTF"]);
        }
        Ok(d.blocking_pick_file().and_then(|f| f.into_path().ok()).map(|p| p.display().to_string()))
    })
    .await
}

#[tauri::command]
async fn save_file(app: AppHandle, default_path: String, ext: String) -> CmdResult<Option<String>> {
    blocking(move || {
        let p = PathBuf::from(&default_path);
        let mut d = app.dialog().file().add_filter(ext.to_uppercase(), &[ext.as_str()]);
        if let Some(dir) = p.parent().filter(|d| d.is_dir()) {
            d = d.set_directory(dir);
        }
        if let Some(n) = p.file_name() {
            d = d.set_file_name(n.to_string_lossy());
        }
        Ok(d.blocking_save_file().and_then(|f| f.into_path().ok()).map(|p| p.display().to_string()))
    })
    .await
}

#[tauri::command]
async fn pdf_pages(path: String) -> CmdResult<Vec<(f32, f32)>> {
    blocking(move || {
        let data = std::fs::read(&path).map_err(|e| format!("Không đọc được file: {e}"))?;
        pdf::page_sizes(&data).map_err(|e| e.to_string())
    })
    .await
}

#[derive(Deserialize)]
struct Visible {
    page: u32,
    rect: [f32; 4],
}

#[derive(Deserialize)]
struct SignPdfReq {
    cert_id: String,
    pin: Option<String>,
    input: String,
    output: String,
    reason: Option<String>,
    location: Option<String>,
    visible: Option<Visible>,
    use_tsa: bool,
}

#[derive(Deserialize)]
struct SignFileReq {
    cert_id: String,
    pin: Option<String>,
    input: String,
    output: String,
    attached: bool,
    use_tsa: bool,
}

#[derive(Deserialize)]
struct SignXmlReq {
    cert_id: String,
    pin: Option<String>,
    input: String,
    output: String,
    profile: String,
    reference_id: Option<String>,
    parent_path: Option<String>,
}

#[derive(Serialize)]
struct SignOutcome {
    output: String,
    detail: String,
}

/// Lỗi trả về giao diện: tiền tố "PIN:" để giao diện biết cần hỏi lại PIN.
fn sign_err(e: linuxsign_core::SignError) -> String {
    match e {
        linuxsign_core::SignError::Pin(m) => format!("PIN:{m}"),
        linuxsign_core::SignError::Failed(m) => m,
    }
}

fn open_signer(app: &AppHandle, cert_id: &str, pin: Option<&str>) -> CmdResult<Signer> {
    let st = app.state::<AppState>();
    let mut report = st.report.lock().unwrap().clone();
    if find_certificate(&report, Some(cert_id)).is_err() {
        report = do_scan(app, false).report;
    }
    let (token, cert) = find_certificate(&report, Some(cert_id)).map_err(|e| e.to_string())?;
    if cert.days_left < 0 {
        return Err("Chứng thư đã hết hạn, chữ ký sẽ không hợp lệ. Hãy gia hạn chứng thư.".into());
    }
    Signer::open(token, cert, pin).map_err(sign_err)
}

#[tauri::command]
async fn sign_pdf(app: AppHandle, req: SignPdfReq) -> CmdResult<SignOutcome> {
    blocking(move || {
        let cfg = Config::load();
        let data = std::fs::read(&req.input).map_err(|e| format!("Không đọc được {}: {e}", req.input))?;
        let mut s = open_signer(&app, &req.cert_id, req.pin.as_deref())?;
        let opts = PdfSignOptions {
            reason: req.reason.filter(|s| !s.is_empty()),
            location: req.location.filter(|s| !s.is_empty()),
            contact: None,
            hash: HashAlg::Sha256,
            pss: false,
            tsa_url: if req.use_tsa { cfg.tsa_url.clone() } else { None },
            visible: req.visible.map(|v| VisibleSignature { page: v.page, rect: v.rect }),
            font: cfg.load_font(),
        };
        let (out, field) = pdf::sign_pdf(&mut s, &data, &opts).map_err(|e| match e {
            pdf::PdfError::Sign(se) => sign_err(se),
            other => other.to_string(),
        })?;
        std::fs::write(&req.output, out).map_err(|e| format!("Không ghi được {}: {e}", req.output))?;
        Ok(SignOutcome { output: req.output, detail: format!("Trường chữ ký {field}, driver {}", s.module()) })
    })
    .await
}

#[tauri::command]
async fn sign_file(app: AppHandle, req: SignFileReq) -> CmdResult<SignOutcome> {
    blocking(move || {
        let cfg = Config::load();
        let data = std::fs::read(&req.input).map_err(|e| format!("Không đọc được {}: {e}", req.input))?;
        let mut s = open_signer(&app, &req.cert_id, req.pin.as_deref())?;
        let opts = CmsOptions {
            attached: req.attached,
            tsa_url: if req.use_tsa { cfg.tsa_url.clone() } else { None },
            ..Default::default()
        };
        let der = cms::sign_data(&mut s, &data, &opts).map_err(sign_err)?;
        std::fs::write(&req.output, der).map_err(|e| format!("Không ghi được {}: {e}", req.output))?;
        Ok(SignOutcome { output: req.output, detail: format!("CMS/PKCS#7, driver {}", s.module()) })
    })
    .await
}

#[tauri::command]
async fn sign_xml(app: AppHandle, req: SignXmlReq) -> CmdResult<SignOutcome> {
    blocking(move || {
        let data = std::fs::read(&req.input).map_err(|e| format!("Không đọc được {}: {e}", req.input))?;
        let profile = XmlProfile::parse(&req.profile).ok_or("Loại chữ ký XML không hợp lệ")?;
        let mut s = open_signer(&app, &req.cert_id, req.pin.as_deref())?;
        let opts = XmlSignOptions {
            profile,
            hash: HashAlg::Sha256,
            reference_id: req.reference_id.filter(|x| !x.trim().is_empty()),
            parent_path: req.parent_path.filter(|x| !x.trim().is_empty()),
            signature_id: None,
        };
        let out = xml::sign_xml(&mut s, &data, &opts).map_err(|e| match e {
            xml::XmlError::Sign(se) => sign_err(se),
            other => other.to_string(),
        })?;
        std::fs::write(&req.output, out).map_err(|e| format!("Không ghi được {}: {e}", req.output))?;
        let label = match profile {
            XmlProfile::EInvoiceVn => "Hóa đơn điện tử (XMLDSig, DSCKS/NBan)",
            XmlProfile::Enveloped => "XMLDSig enveloped",
            XmlProfile::Xades => "XAdES-BES",
        };
        Ok(SignOutcome { output: req.output, detail: format!("{label}, driver {}", s.module()) })
    })
    .await
}

fn find_cert(app: &AppHandle, cert_id: &str) -> CmdResult<linuxsign_core::certinfo::CertInfo> {
    let r = app.state::<AppState>().report.lock().unwrap().clone();
    find_certificate(&r, Some(cert_id)).map(|(_, c)| c.clone()).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_cert(app: AppHandle, cert_id: String, path: String) -> CmdResult<()> {
    let c = find_cert(&app, &cert_id)?;
    let b64 = c.der_b64.as_bytes().chunks(64).map(|l| String::from_utf8_lossy(l).to_string()).collect::<Vec<_>>().join("\n");
    std::fs::write(&path, format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")).map_err(|e| e.to_string())
}

/// Xuất nhắc lịch (.ics) cho ngày hết hạn, có báo trước `remind_days` ngày; mở bằng Lịch Google/Outlook/Thunderbird.
#[tauri::command]
fn export_ics(app: AppHandle, cert_id: String, path: String, remind_days: i64) -> CmdResult<()> {
    let c = find_cert(&app, &cert_id)?;
    let end = chrono::DateTime::parse_from_rfc3339(&c.not_after).map_err(|e| e.to_string())?;
    let day = end.format("%Y%m%d");
    let esc = |s: &str| s.replace('\\', "\\\\").replace(',', "\\,").replace(';', "\\;");
    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//LinuxSign//VN\r\nBEGIN:VEVENT\r\nUID:{id}@linuxsign\r\nDTSTAMP:{now}\r\nDTSTART;VALUE=DATE:{day}\r\nSUMMARY:{sum}\r\nDESCRIPTION:{desc}\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:{sum}\r\nTRIGGER:-P{rd}D\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        id = c.cert_id,
        now = chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
        sum = esc(&format!("Hết hạn chữ ký số: {}", c.subject_cn)),
        desc = esc(&format!("Nhà cung cấp: {}. Serial: {}. Liên hệ nhà cung cấp để gia hạn trước ngày này.", c.issuer_o.as_deref().unwrap_or(&c.issuer_cn), c.serial_hex)),
        rd = remind_days.max(1),
    );
    std::fs::write(&path, ics).map_err(|e| e.to_string())
}

/// Mở file bằng ứng dụng mặc định, hoặc mở thư mục chứa file (reveal = true).
#[tauri::command]
fn open_path(app: AppHandle, path: String, reveal: bool) -> CmdResult<()> {
    use tauri_plugin_opener::OpenerExt;
    if reveal {
        app.opener().reveal_item_in_dir(&path).map_err(|e| e.to_string())
    } else {
        app.opener().open_path(&path, None::<&str>).map_err(|e| e.to_string())
    }
}

fn main() {
    // Tiến trình con thăm dò driver: chạy và thoát trước khi khởi tạo giao diện.
    probe::maybe_run_probe_mode();

    tauri::Builder::default()
        // Khởi động cùng hệ thống: chạy ẩn ở khay (--minimized)
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec!["--minimized"])))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .setup(|app| {
            let cfg = Config::load();
            apply_agent(app.handle(), &cfg);
            tray::setup(app.handle())?;
            if std::env::args().any(|a| a == "--minimized") {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Đóng cửa sổ → ẩn xuống khay, agent và giám sát hạn vẫn chạy
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" && Config::load().run_in_background {
                    api.prevent_close();
                    let _ = window.hide();
                    let st = window.app_handle().state::<AppState>();
                    if !st.hinted_tray.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        let _ = window
                            .app_handle()
                            .notification()
                            .builder()
                            .title("LinuxSign vẫn đang chạy")
                            .body("Ứng dụng tiếp tục theo dõi token và hạn chứng thư ở khay hệ thống. Chọn \"Thoát LinuxSign\" trong menu khay để tắt hẳn.")
                            .show();
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            scan_tokens, run_doctor, get_config, save_config, agent_status, pick_file, save_file,
            pdf_pages, sign_pdf, sign_file, sign_xml, export_cert, export_ics, open_path,
            get_autostart, set_autostart
        ])
        .run(tauri::generate_context!())
        .expect("không khởi động được ứng dụng");
}
