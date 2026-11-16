//! LinuxSign core: ký số bằng USB Token qua chuẩn PKCS#11, chạy trên Linux, Windows, macOS.
//!
//! Luồng xử lý:
//!   discovery → tìm mọi thư viện PKCS#11 trên máy (không nạp)
//!   probe     → nạp từng thư viện trong tiến trình con riêng (driver crash/treo không lan)
//!   manager   → gộp token trùng, chọn driver chính + dự phòng
//!   signer    → ký với chuỗi cơ chế dự phòng, luôn xác minh lại chữ ký
//!   cms / pdf → đóng gói chữ ký CMS (CAdES) và PDF (PAdES), kèm dấu thời gian (tsa)
//!   agent     → HTTP localhost cho ứng dụng web

pub mod agent;
pub mod certinfo;
pub mod cms;
pub mod config;
pub mod der;
pub mod discovery;
pub mod doctor;
pub mod font;
pub mod manager;
pub mod pdf;
pub mod probe;
pub mod registry;
pub mod signer;
pub mod tsa;
pub mod xml;

pub use config::Config;
pub use manager::{find_certificate, scan, Report, TokenInfo};
pub use signer::{HashAlg, SignError, Signer};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Tham số dòng lệnh ẩn để chạy chế độ thăm dò trong tiến trình con.
/// CLI và ứng dụng desktop đều phải gọi `probe::maybe_run_probe_mode()` đầu tiên trong `main`.
pub const PROBE_ARG: &str = "__linuxsign_probe";
