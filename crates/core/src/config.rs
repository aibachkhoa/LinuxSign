//! Cấu hình người dùng: ~/.config/linuxsign/config.json (Windows: %APPDATA%\linuxsign\config.json).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Đường dẫn driver PKCS#11 khai báo thêm (luôn được dùng, kể cả khi nằm trong danh sách loại trừ).
    pub extra_modules: Vec<String>,
    /// Thư mục quét sâu thêm.
    pub extra_search_dirs: Vec<String>,
    /// Mẫu tên driver cần bỏ qua (glob).
    pub exclude_modules: Vec<String>,
    /// Độ ưu tiên driver (tên file hoặc đường dẫn → số; lớn hơn thắng).
    pub module_priority: HashMap<String, i32>,
    /// Bật agent HTTP localhost khi mở ứng dụng.
    pub agent_enabled: bool,
    pub agent_port: u16,
    /// Origin web được phép gọi agent, ví dụ "https://app.congty.vn".
    pub agent_allowed_origins: Vec<String>,
    /// Cảnh báo khi chứng thư còn ít hơn số ngày này.
    pub expiry_warn_days: i64,
    /// Máy chủ dấu thời gian mặc định (RFC 3161), để trống nếu không dùng.
    pub tsa_url: Option<String>,
    /// Thông tin hiển thị mặc định khi ký PDF.
    pub default_reason: Option<String>,
    pub default_location: Option<String>,
    /// File font TrueType (.ttf) cho khung chữ ký PDF; trống = Noto Sans đi kèm.
    pub signature_font: Option<String>,
    /// Đóng cửa sổ thì thu nhỏ xuống khay hệ thống thay vì thoát.
    pub run_in_background: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            extra_modules: vec![],
            extra_search_dirs: vec![],
            exclude_modules: vec![],
            module_priority: HashMap::new(),
            agent_enabled: false,
            agent_port: 18080,
            agent_allowed_origins: vec![],
            expiry_warn_days: 30,
            tsa_url: None,
            default_reason: None,
            default_location: None,
            signature_font: None,
            run_in_background: true,
        }
    }
}

impl Config {
    pub fn path() -> PathBuf {
        if let Ok(p) = std::env::var("LINUXSIGN_CONFIG") {
            return PathBuf::from(p);
        }
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("linuxsign")
            .join("config.json")
    }

    pub fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Đọc font khung chữ ký do người dùng chọn (nếu có).
    pub fn load_font(&self) -> Option<Vec<u8>> {
        self.signature_font.as_deref().filter(|p| !p.is_empty()).and_then(|p| std::fs::read(p).ok())
    }

    pub fn save(&self) -> std::io::Result<()> {
        let p = Self::path();
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(p, serde_json::to_vec_pretty(self).expect("serialize config"))
    }
}
