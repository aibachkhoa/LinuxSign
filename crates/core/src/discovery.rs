//! Tìm mọi thư viện PKCS#11 trên máy. Chỉ ĐỌC file, không nạp thư viện.
//!
//! Nguồn, theo thứ tự ưu tiên:
//!   1. Biến môi trường LINUXSIGN_MODULES và `extra_modules` trong cấu hình
//!   2. Module đăng ký với p11-kit (Linux)
//!   3. Tên driver đã biết (registry) trong thư mục hệ thống
//!   4. Quét sâu /opt, /usr/local/lib, Program Files: thư viện nào chứa chuỗi
//!      `C_GetFunctionList` là driver PKCS#11. Nhờ vậy nhận được cả hãng chưa biết.

use crate::config::Config;
use crate::registry::{os_patterns, DRIVER_HINTS, EXCLUDED_MODULES};
use glob::Pattern;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

const SYMBOL: &[u8] = b"C_GetFunctionList";
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
const DEEP_MAX_DEPTH: usize = 5;

#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub path: String,
    pub vendor: String,
    pub priority: i32,
    /// env | config | p11-kit | hint | scan
    pub source: String,
}

fn lib_exts() -> &'static [&'static str] {
    if cfg!(windows) {
        &[".dll"]
    } else if cfg!(target_os = "macos") {
        &[".dylib", ".so"]
    } else {
        &[".so"]
    }
}

fn is_lib_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    lib_exts().iter().any(|e| n.ends_with(e) || n.contains(&format!("{e}.")))
}

fn multiarch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-linux-gnu",
        "aarch64" => "aarch64-linux-gnu",
        "arm" => "arm-linux-gnueabihf",
        "x86" => "i386-linux-gnu",
        _ => "x86_64-linux-gnu",
    }
}

/// Thư mục hệ thống: chỉ tra theo tên trong registry.
pub fn standard_dirs() -> Vec<PathBuf> {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        return vec![Path::new(&root).join("System32")];
    }
    if cfg!(target_os = "macos") {
        return ["/usr/local/lib", "/opt/homebrew/lib", "/Library/OpenSC/lib", "/usr/local/lib/pkcs11"]
            .iter()
            .map(PathBuf::from)
            .collect();
    }
    let ma = multiarch();
    [
        "/usr/lib".to_string(), format!("/usr/lib/{ma}"), format!("/usr/lib/{ma}/pkcs11"),
        "/usr/lib/pkcs11".into(), "/usr/lib64".into(), "/usr/lib64/pkcs11".into(),
        format!("/lib/{ma}"), "/usr/local/lib".into(), "/usr/local/lib/pkcs11".into(),
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

/// Thư mục bộ cài của hãng hay đặt driver: quét đệ quy.
pub fn deep_dirs(cfg: &Config) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = cfg.extra_search_dirs.iter().map(|d| expand_home(d)).collect();
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramW6432"] {
            if let Ok(p) = std::env::var(var) {
                v.push(PathBuf::from(p));
            }
        }
    } else if cfg!(target_os = "macos") {
        v.extend(["/Library", "/usr/local/lib", "/opt"].iter().map(PathBuf::from));
    } else {
        let ma = multiarch();
        v.extend(
            ["/opt".to_string(), "/usr/local/lib".into(), "/usr/lib/pkcs11".into(), format!("/usr/lib/{ma}/pkcs11")]
                .into_iter()
                .map(PathBuf::from),
        );
    }
    v.dedup();
    v
}

fn expand_home(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => dirs::home_dir().unwrap_or_default().join(rest),
        None => PathBuf::from(p),
    }
}

/// File có chứa ký hiệu C_GetFunctionList không (đọc theo khối, không nạp thư viện).
pub fn has_pkcs11_symbol(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false };
    if !meta.is_file() || meta.len() > MAX_SCAN_BYTES {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let mut buf = vec![0u8; 1 << 20];
    let mut carry: Vec<u8> = Vec::new();
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) | Err(_) => return false,
            Ok(n) => n,
        };
        carry.extend_from_slice(&buf[..n]);
        if carry.windows(SYMBOL.len()).any(|w| w == SYMBOL) {
            return true;
        }
        let keep = carry.len().saturating_sub(SYMBOL.len());
        carry.drain(..keep);
    }
}

fn matches_any(name: &str, full: &str, patterns: impl IntoIterator<Item = impl AsRef<str>>) -> bool {
    patterns.into_iter().any(|p| {
        Pattern::new(p.as_ref())
            .map(|pat| pat.matches(name) || pat.matches(full))
            .unwrap_or(false)
    })
}

fn hint_for(path: &Path) -> Option<(&'static str, i32)> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    DRIVER_HINTS.iter().find_map(|h| {
        os_patterns(h)
            .iter()
            .any(|p| Pattern::new(&p.to_ascii_lowercase()).map(|pt| pt.matches(&name)).unwrap_or(false))
            .then_some((h.vendor, h.priority))
    })
}

fn p11kit_modules() -> Vec<PathBuf> {
    if cfg!(windows) {
        return vec![];
    }
    let mut dirs_ = vec![PathBuf::from("/usr/share/p11-kit/modules"), PathBuf::from("/etc/pkcs11/modules")];
    if let Some(h) = dirs::home_dir() {
        dirs_.push(h.join(".config/pkcs11/modules"));
    }
    let default_dir = PathBuf::from(format!("/usr/lib/{}/pkcs11", multiarch()));
    let mut out = vec![];
    for d in dirs_ {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        let mut files: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        files.sort();
        for f in files.into_iter().filter(|f| f.extension().is_some_and(|e| e == "module")) {
            let Ok(text) = std::fs::read_to_string(&f) else { continue };
            for line in text.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim() == "module" && !v.trim().is_empty() {
                        let p = PathBuf::from(v.trim());
                        out.push(if p.is_absolute() { p } else { default_dir.join(p) });
                    }
                }
            }
        }
    }
    out
}

pub fn discover(cfg: &Config, deep: bool) -> Vec<Candidate> {
    let mut out: HashMap<String, Candidate> = HashMap::new();

    let mut add = |path: &Path, source: &str, vendor: Option<&str>, priority: Option<i32>| {
        let Ok(real) = std::fs::canonicalize(path) else { return };
        let real_s = real.to_string_lossy().to_string();
        if out.contains_key(&real_s) || !real.is_file() {
            return;
        }
        let user_given = matches!(source, "env" | "config");
        if !user_given {
            for p in [path, real.as_path()] {
                let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                let full = p.to_string_lossy();
                if matches_any(&name, &full, EXCLUDED_MODULES) || matches_any(&name, &full, &cfg.exclude_modules) {
                    return;
                }
            }
        }
        if matches!(source, "hint" | "scan") && !has_pkcs11_symbol(&real) {
            return;
        }
        let hint = hint_for(path).or_else(|| hint_for(&real));
        let vendor = vendor
            .map(str::to_string)
            .or(hint.map(|h| h.0.to_string()))
            .unwrap_or_else(|| "Không rõ (phát hiện tự động)".into());
        let mut prio = priority.or(hint.map(|h| h.1)).unwrap_or(60);
        let fname = real.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if let Some(p) = cfg.module_priority.get(&real_s).or_else(|| cfg.module_priority.get(&fname)) {
            prio = *p;
        }
        out.insert(real_s.clone(), Candidate { path: real_s, vendor, priority: prio, source: source.into() });
    };

    if let Ok(env) = std::env::var("LINUXSIGN_MODULES") {
        for p in std::env::split_paths(&env) {
            add(&p, "env", None, Some(100));
        }
    }
    for p in &cfg.extra_modules {
        add(&expand_home(p), "config", None, Some(95));
    }
    for p in p11kit_modules() {
        add(&p, "p11-kit", None, None);
    }
    for d in standard_dirs().into_iter().filter(|d| d.is_dir()) {
        for h in DRIVER_HINTS {
            for pat in os_patterns(h) {
                let Ok(paths) = glob::glob(&d.join(pat).to_string_lossy()) else { continue };
                for m in paths.flatten() {
                    add(&m, "hint", Some(h.vendor), Some(h.priority));
                }
            }
        }
    }
    if deep {
        for root in deep_dirs(cfg).into_iter().filter(|d| d.is_dir()) {
            for e in walkdir::WalkDir::new(&root).max_depth(DEEP_MAX_DEPTH).into_iter().flatten() {
                if e.file_type().is_file() && is_lib_name(&e.file_name().to_string_lossy()) {
                    add(e.path(), "scan", None, None);
                }
            }
        }
    }

    let mut v: Vec<Candidate> = out.into_values().collect();
    v.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.path.cmp(&b.path)));
    v
}
