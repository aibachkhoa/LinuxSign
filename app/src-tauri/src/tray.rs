//! Biểu tượng khay hệ thống và giám sát nền.
//!
//! - Menu khay: mở cửa sổ, trạng thái token, tình trạng hạn chứng thư, bật/tắt agent,
//!   khởi động cùng hệ thống, quét lại, thoát.
//! - Đóng cửa sổ → ẩn xuống khay (nếu bật "chạy nền"); agent và giám sát vẫn chạy.
//! - Luồng giám sát: định kỳ thăm dò token, cập nhật menu, thông báo khi cắm/rút token
//!   (lúc cửa sổ đang ẩn) và khi chứng thư sắp hết hạn.

use crate::{apply_agent, do_scan, AppState};
use linuxsign_core::Config;
use std::collections::BTreeMap;
use std::time::Duration;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};
use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_notification::NotificationExt;

/// Chu kỳ giám sát nền.
const MONITOR_INTERVAL: Duration = Duration::from_secs(60);

pub struct TrayHandles {
    status: MenuItem<Wry>,
    expiry: MenuItem<Wry>,
    agent: CheckMenuItem<Wry>,
    autostart: CheckMenuItem<Wry>,
}

/// Chạy `f` với các mục menu khay, nếu khay đã được tạo.
fn with_handles(app: &AppHandle, f: impl FnOnce(&TrayHandles)) {
    if let Some(m) = app.try_state::<std::sync::Mutex<Option<TrayHandles>>>() {
        if let Ok(g) = m.lock() {
            if let Some(h) = g.as_ref() {
                f(h);
            }
        }
    }
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let cfg = Config::load();
    let open = MenuItem::with_id(app, "open", "Mở LinuxSign", true, None::<&str>)?;
    let status = MenuItem::with_id(app, "status", "Đang quét token…", false, None::<&str>)?;
    let expiry = MenuItem::with_id(app, "expiry", "—", false, None::<&str>)?;
    let agent = CheckMenuItem::with_id(app, "agent", "Signing agent cho web", true, cfg.agent_enabled, None::<&str>)?;
    let auto_on = app.autolaunch().is_enabled().unwrap_or(false);
    let autostart = CheckMenuItem::with_id(app, "autostart", "Khởi động cùng hệ thống", true, auto_on, None::<&str>)?;
    let rescan = MenuItem::with_id(app, "rescan", "Quét lại token", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Thoát LinuxSign", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &open,
            &PredefinedMenuItem::separator(app)?,
            &status,
            &expiry,
            &PredefinedMenuItem::separator(app)?,
            &agent,
            &autostart,
            &rescan,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;

    TrayIconBuilder::with_id("linuxsign")
        .icon(app.default_window_icon().cloned().expect("có icon ứng dụng"))
        .tooltip("LinuxSign")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| match ev.id.as_ref() {
            "open" => show_main(app),
            "agent" => toggle_agent(app),
            "autostart" => {
                let _ = set_autostart(app, !app.autolaunch().is_enabled().unwrap_or(false));
            }
            "rescan" => {
                let app = app.clone();
                std::thread::spawn(move || {
                    let r = do_scan(&app, true);
                    refresh(&app, &r.report, r.warn_days);
                    let _ = app.emit("tokens-changed", ());
                });
            }
            "quit" => {
                if let Some(h) = app.state::<AppState>().agent.lock().unwrap().take() {
                    h.stop();
                }
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, ev| {
            // Windows/macOS: bấm chuột trái vào biểu tượng để mở cửa sổ (Linux dùng menu).
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;

    app.manage(std::sync::Mutex::new(Some(TrayHandles { status, expiry, agent, autostart })));
    spawn_monitor(app.clone());
    Ok(())
}

fn toggle_agent(app: &AppHandle) {
    let mut cfg = Config::load();
    cfg.agent_enabled = !cfg.agent_enabled;
    let _ = cfg.save();
    apply_agent(app, &cfg);
    let running = app.state::<AppState>().agent.lock().unwrap().is_some();
    set_agent_checked(app, running);
    let _ = app.emit("config-changed", ());
}

pub fn set_agent_checked(app: &AppHandle, on: bool) {
    with_handles(app, |h| {
        let _ = h.agent.set_checked(on);
    });
}

pub fn set_autostart(app: &AppHandle, on: bool) -> Result<(), String> {
    let al = app.autolaunch();
    if on { al.enable() } else { al.disable() }.map_err(|e| e.to_string())?;
    with_handles(app, |h| {
        let _ = h.autostart.set_checked(on);
    });
    Ok(())
}

/// Cập nhật dòng trạng thái và tooltip trên khay theo kết quả quét.
pub fn refresh(app: &AppHandle, r: &linuxsign_core::Report, warn_days: i64) {
    let certs: Vec<_> = r.tokens.iter().flat_map(|t| &t.certificates).collect();
    let expired = certs.iter().filter(|c| c.status(warn_days) == "expired").count();
    let expiring = certs.iter().filter(|c| c.status(warn_days) == "expiring").count();
    let status = match r.tokens.len() {
        0 => "Chưa cắm USB Token".to_string(),
        1 => format!("Token: {} ({} chứng thư)", r.tokens[0].label, certs.len()),
        n => format!("{n} token, {} chứng thư", certs.len()),
    };
    let expiry = match (expired, expiring) {
        (0, 0) if certs.is_empty() => "—".to_string(),
        (0, 0) => {
            let min = certs.iter().map(|c| c.days_left).min().unwrap_or(0);
            format!("Còn hạn (gần nhất: {min} ngày)")
        }
        (0, n) => format!("⚠ {n} chứng thư sắp hết hạn"),
        (e, 0) => format!("⛔ {e} chứng thư đã hết hạn"),
        (e, n) => format!("⛔ {e} hết hạn, ⚠ {n} sắp hết hạn"),
    };
    with_handles(app, |h| {
        let _ = h.status.set_text(&status);
        let _ = h.expiry.set_text(&expiry);
    });
    if let Some(tray) = app.tray_by_id("linuxsign") {
        let _ = tray.set_tooltip(Some(format!("LinuxSign\n{status}\n{expiry}")));
    }
}

fn window_visible(app: &AppHandle) -> bool {
    app.get_webview_window("main").and_then(|w| w.is_visible().ok()).unwrap_or(false)
}

/// Luồng nền: quét định kỳ, cập nhật khay, báo cắm/rút token khi cửa sổ đang ẩn.
fn spawn_monitor(app: AppHandle) {
    std::thread::spawn(move || {
        let mut known: Option<BTreeMap<String, String>> = None;
        let mut first = true;
        loop {
            let r = do_scan(&app, first);
            first = false;
            refresh(&app, &r.report, r.warn_days);
            let now: BTreeMap<String, String> = r.report.tokens.iter().map(|t| (t.token_id.clone(), t.label.clone())).collect();
            if let Some(prev) = &known {
                if !window_visible(&app) {
                    for (id, label) in &now {
                        if !prev.contains_key(id) {
                            let _ = app.notification().builder().title("LinuxSign").body(format!("Đã nhận USB Token \"{label}\"")).show();
                        }
                    }
                    for (id, label) in prev {
                        if !now.contains_key(id) {
                            let _ = app.notification().builder().title("LinuxSign").body(format!("Đã rút USB Token \"{label}\"")).show();
                        }
                    }
                }
                if prev != &now {
                    let _ = app.emit("tokens-changed", ());
                }
            }
            known = Some(now);
            std::thread::sleep(MONITOR_INTERVAL);
        }
    });
}
