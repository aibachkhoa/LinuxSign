//! Gợi ý tên driver PKCS#11 đã biết.
//!
//! Đây CHỈ là gợi ý để tìm nhanh và gắn nhãn hãng. Cơ chế chính là quét mọi thư viện
//! export `C_GetFunctionList` (discovery.rs), nên token của hãng chưa có ở đây vẫn
//! được nhận nếu driver đã được cài.

pub struct DriverHint {
    pub vendor: &'static str,
    pub linux: &'static [&'static str],
    pub windows: &'static [&'static str],
    pub macos: &'static [&'static str],
    /// Lớn hơn thắng khi cùng một token được nhiều driver nhìn thấy (driver hãng > OpenSC).
    pub priority: i32,
}

pub const DRIVER_HINTS: &[DriverHint] = &[
    DriverHint {
        vendor: "SafeNet / Thales (eToken, IDPrime)",
        linux: &["libeTPkcs11.so", "libIDPrimePKCS11.so"],
        windows: &["eTPKCS11.dll", "IDPrimePKCS11.dll"],
        macos: &["libeTPkcs11.dylib", "libIDPrimePKCS11.dylib"],
        priority: 80,
    },
    DriverHint {
        vendor: "Feitian (ePass2003, ...)",
        linux: &["libcastle.so*", "libshuttle_p11v220.so*", "libes_3003_pkcs11*.so"],
        windows: &["eps2003csp11.dll", "ShuttleCsp11_3003.dll"],
        macos: &["libcastle.dylib"],
        priority: 70,
    },
    DriverHint {
        vendor: "Longmai (mToken)",
        linux: &["libgm3000*.so*", "libmtoken*.so*"],
        windows: &["mtoken_gm3000*.dll", "gm3000*.dll"],
        macos: &[],
        priority: 70,
    },
    DriverHint {
        vendor: "Bit4id",
        linux: &["libbit4ipki.so*", "libbit4xpki.so*"],
        windows: &["bit4ipki.dll", "bit4xpki.dll"],
        macos: &["libbit4ipki.dylib", "libbit4xpki.dylib"],
        priority: 70,
    },
    DriverHint {
        vendor: "Watchdata",
        linux: &["libwdpkcs*.so*", "libWDP11*.so*"],
        windows: &["WDPKCS*.dll", "WDP11*.dll"],
        macos: &[],
        priority: 70,
    },
    DriverHint {
        vendor: "CA Việt Nam (Viettel, VNPT, BKAV, FPT, Nacencomm, MISA, EasyCA, ...)",
        linux: &[
            "*viettel*.so*", "*vnpt*.so*", "*bkav*.so*", "*fpt*ca*.so*", "*nacencomm*.so*",
            "*ca2*pkcs*.so*", "*misa*.so*", "*easyca*.so*", "*safecert*.so*", "*newtel*.so*",
            "*smartsign*.so*",
        ],
        windows: &[
            "*viettel*.dll", "*vnpt*.dll", "*bkav*.dll", "*fpt*ca*.dll", "*nacencomm*.dll",
            "*ca2*.dll", "*misa*.dll", "*easyca*.dll", "*safecert*.dll", "*newtel*.dll",
        ],
        macos: &[],
        priority: 75,
    },
    DriverHint {
        vendor: "OpenSC (mã nguồn mở, hỗ trợ nhiều chip)",
        linux: &["opensc-pkcs11.so"],
        windows: &["opensc-pkcs11.dll"],
        macos: &["opensc-pkcs11.so"],
        priority: 40,
    },
];

/// Module không bao giờ chứa khóa ký của người dùng.
pub const EXCLUDED_MODULES: &[&str] = &[
    "p11-kit-proxy.so", "p11-kit-trust.so", "p11-kit-client.so",
    "gnome-keyring-pkcs11.so", "libnvidia-pkcs11*",
];

/// USB Vendor ID → hãng; dùng cho chẩn đoán.
pub const USB_VENDORS: &[(&str, &str)] = &[
    ("0529", "SafeNet / Aladdin (eToken)"),
    ("08e6", "Gemalto / Thales"),
    ("096e", "Feitian"),
    ("163c", "Watchdata"),
    ("25dd", "Bit4id"),
    ("072f", "ACS (đầu đọc thẻ)"),
    ("04e6", "SCM / Identiv (đầu đọc thẻ)"),
    ("076b", "OmniKey / HID (đầu đọc thẻ)"),
];

pub fn os_patterns(h: &DriverHint) -> &'static [&'static str] {
    if cfg!(windows) {
        h.windows
    } else if cfg!(target_os = "macos") {
        h.macos
    } else {
        h.linux
    }
}
