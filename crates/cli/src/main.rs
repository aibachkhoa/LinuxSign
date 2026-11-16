//! linuxsign: CLI ký số bằng USB Token.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use linuxsign_core::cms::{self, CmsOptions};
use linuxsign_core::pdf::{self, PdfSignOptions, VisibleSignature};
use linuxsign_core::xml::{self, XmlProfile, XmlSignOptions};
use linuxsign_core::{doctor, find_certificate, probe, scan, Config, HashAlg, Signer};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "linuxsign", version, about = "Ký số bằng USB Token (PKCS#11) trên Linux, Windows, macOS")]
struct Cli {
    /// Bỏ qua quét sâu /opt, Program Files (nhanh hơn)
    #[arg(long, global = true)]
    fast: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Chẩn đoán: dịch vụ smart card, USB, driver, token, hạn chứng thư
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Liệt kê token và chứng thư (không cần PIN)
    List {
        #[arg(long)]
        json: bool,
    },
    /// Kiểm tra hạn chứng thư; mã thoát 1 nếu có chứng thư sắp/đã hết hạn (dùng cho cron)
    Expiry {
        #[arg(long)]
        days: Option<i64>,
    },
    /// Ký file bất kỳ → CMS/PKCS#7 (.p7s)
    Sign {
        file: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Chỉ xuất chữ ký thô (.sig)
        #[arg(long)]
        raw: bool,
        /// CMS chứa luôn dữ liệu gốc
        #[arg(long)]
        attached: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Ký PDF chuẩn PAdES
    SignPdf {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        location: Option<String>,
        /// Khung chữ ký hiển thị: x1,y1,x2,y2 (điểm PDF, gốc góc dưới trái)
        #[arg(long)]
        rect: Option<String>,
        #[arg(long, default_value_t = 1)]
        page: u32,
        #[command(flatten)]
        common: Common,
    },
    /// Ký XML: hóa đơn điện tử (einvoice), tờ khai/văn bản XML (enveloped), XAdES-BES (xades)
    SignXml {
        input: PathBuf,
        output: PathBuf,
        /// einvoice | enveloped | xades
        #[arg(long, default_value = "enveloped")]
        profile: String,
        /// Id phần tử cần ký (URI="#id"); mặc định: toàn văn bản, hoặc DLHDon với einvoice
        #[arg(long = "ref-id")]
        ref_id: Option<String>,
        /// Nơi đặt chữ ký tính từ phần tử gốc, ví dụ DSCKS/NBan (thiếu thì tạo)
        #[arg(long)]
        parent: Option<String>,
        /// Id của phần tử Signature
        #[arg(long = "sig-id")]
        sig_id: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Chạy signing agent HTTP ở localhost cho ứng dụng web
    Serve {
        #[arg(long)]
        port: Option<u16>,
        /// Origin web được phép, ví dụ https://app.congty.vn (lặp lại được)
        #[arg(long = "allow-origin")]
        allow_origin: Vec<String>,
    },
}

#[derive(Args)]
struct Common {
    /// cert_id (hoặc tiền tố), serial, MST, hoặc một phần tên
    #[arg(long)]
    cert: Option<String>,
    /// Mã PIN (nên dùng biến LINUXSIGN_PIN hoặc nhập khi được hỏi)
    #[arg(long)]
    pin: Option<String>,
    #[arg(long, default_value = "sha256")]
    hash: String,
    /// Dùng RSA-PSS thay vì PKCS#1 v1.5
    #[arg(long)]
    pss: bool,
    /// Máy chủ dấu thời gian RFC 3161
    #[arg(long)]
    tsa: Option<String>,
}

fn open_signer(cfg: &Config, fast: bool, c: &Common) -> Result<(Signer, HashAlg)> {
    let hash = HashAlg::parse(&c.hash).context("thuật toán băm không hỗ trợ")?;
    let report = scan(cfg, !fast);
    let (token, cert) = find_certificate(&report, c.cert.as_deref())?;
    eprintln!("Ký bằng: {} (token {}, còn {} ngày)", cert.subject_cn, token.label, cert.days_left);
    if cert.days_left < 0 {
        bail!("Chứng thư đã hết hạn, chữ ký sẽ không hợp lệ.");
    }
    let pin = match c.pin.clone().or_else(|| std::env::var("LINUXSIGN_PIN").ok()) {
        Some(p) => Some(p),
        None if token.protected_auth_path => {
            eprintln!("Token có PIN pad: hãy nhập PIN trên thiết bị.");
            None
        }
        None => Some(rpassword::prompt_password(format!("PIN cho token \"{}\": ", token.label))?),
    };
    Ok((Signer::open(token, cert, pin.as_deref())?, hash))
}

fn status_label(s: &str) -> &'static str {
    match s {
        "expired" => "HẾT HẠN",
        "expiring" => "SẮP HẾT HẠN",
        "not_yet_valid" => "CHƯA HIỆU LỰC",
        _ => "còn hạn",
    }
}

fn main() -> Result<()> {
    probe::maybe_run_probe_mode();
    let cli = Cli::parse();
    let cfg = Config::load();
    match cli.cmd {
        Cmd::Doctor { json } => {
            let r = doctor::run(&cfg, !cli.fast);
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
                return Ok(());
            }
            println!("LinuxSign {} | {}", r.version, r.os);
            println!("Cấu hình: {}", Config::path().display());
            match r.pcscd_running {
                Some(true) => println!("[pcscd]  đang chạy"),
                Some(false) => println!("[pcscd]  KHÔNG chạy"),
                None => {}
            }
            for d in &r.usb_devices {
                println!("[USB]    {}  {}  → {}", d.id, d.product, d.vendor_hint);
            }
            println!("[Driver] {} thư viện PKCS#11:", r.modules.len());
            for m in &r.modules {
                let st = m.error.clone().map(|e| format!("LỖI: {e}")).unwrap_or(format!("{} token", m.token_count));
                println!("   - {}\n       {} | nguồn: {} | {}", m.candidate.path, m.candidate.vendor, m.candidate.source, st);
            }
            println!("[Token]  {} token, {} chứng thư", r.token_count, r.certificate_count);
            if !r.advice.is_empty() {
                println!("\nKhuyến nghị:");
                for a in &r.advice {
                    println!("  • {a}");
                }
            }
        }
        Cmd::List { json } => {
            let r = scan(&cfg, !cli.fast);
            if json {
                println!("{}", serde_json::to_string_pretty(&r.tokens)?);
                return Ok(());
            }
            if r.tokens.is_empty() {
                println!("Không thấy token nào. Chạy `linuxsign doctor` để chẩn đoán.");
                std::process::exit(1);
            }
            for t in &r.tokens {
                println!("Token: {}  [{} {}, serial {}]", t.label, t.manufacturer, t.model, t.serial);
                println!("  driver: {}{}", t.routes[0].module, if t.routes.len() > 1 { format!("  (+{} dự phòng)", t.routes.len() - 1) } else { String::new() });
                for c in &t.certificates {
                    println!("  • {}  {}", &c.cert_id[..16], c.subject_cn);
                    if let Some(m) = &c.tax_code {
                        println!("      MST: {m}");
                    }
                    println!(
                        "      cấp bởi: {} | hết hạn: {} ({} ngày, {}) | {} {}",
                        c.issuer_cn, &c.not_after[..10], c.days_left, status_label(c.status(cfg.expiry_warn_days)),
                        c.key_type, c.key_size.unwrap_or(0)
                    );
                }
            }
        }
        Cmd::Expiry { days } => {
            let warn = days.unwrap_or(cfg.expiry_warn_days);
            let r = scan(&cfg, !cli.fast);
            let mut bad = false;
            for c in r.tokens.iter().flat_map(|t| &t.certificates) {
                let st = c.status(warn);
                bad |= st != "valid";
                println!("{:<14} {:>5} ngày  {}  ({})", status_label(st), c.days_left, c.subject_cn, &c.not_after[..10]);
            }
            if bad {
                std::process::exit(1);
            }
        }
        Cmd::Sign { file, out, raw, attached, common } => {
            let data = std::fs::read(&file).with_context(|| format!("không đọc được {}", file.display()))?;
            let (mut s, hash) = open_signer(&cfg, cli.fast, &common)?;
            let tsa = common.tsa.or(cfg.tsa_url.clone());
            if raw {
                let r = s.sign(Some(&data), None, hash, common.pss)?;
                let out = out.unwrap_or_else(|| PathBuf::from(format!("{}.sig", file.display())));
                std::fs::write(&out, &r.signature)?;
                println!("Đã ký ({} qua {}) → {}", r.mechanism, r.module, out.display());
            } else {
                let der = cms::sign_data(&mut s, &data, &CmsOptions { hash, pss: common.pss, attached, tsa_url: tsa, pades: false })?;
                let out = out.unwrap_or_else(|| PathBuf::from(format!("{}.p7s", file.display())));
                std::fs::write(&out, der)?;
                println!("Đã ký CMS/PKCS#7 → {}", out.display());
            }
        }
        Cmd::SignPdf { input, output, reason, location, rect, page, common } => {
            let data = std::fs::read(&input).with_context(|| format!("không đọc được {}", input.display()))?;
            let visible = match rect {
                Some(r) => {
                    let v: Vec<f32> = r.split(',').map(|x| x.trim().parse()).collect::<Result<_, _>>().context("--rect phải là x1,y1,x2,y2")?;
                    if v.len() != 4 {
                        bail!("--rect phải có 4 số");
                    }
                    Some(VisibleSignature { page, rect: [v[0], v[1], v[2], v[3]] })
                }
                None => None,
            };
            let (mut s, hash) = open_signer(&cfg, cli.fast, &common)?;
            let opts = PdfSignOptions {
                reason: reason.or(cfg.default_reason.clone()),
                location: location.or(cfg.default_location.clone()),
                contact: None,
                hash,
                pss: common.pss,
                tsa_url: common.tsa.or(cfg.tsa_url.clone()),
                visible,
                font: cfg.load_font(),
            };
            let (out, field) = pdf::sign_pdf(&mut s, &data, &opts)?;
            std::fs::write(&output, out)?;
            println!("Đã ký PDF (trường {field}) → {}", output.display());
        }
        Cmd::SignXml { input, output, profile, ref_id, parent, sig_id, common } => {
            let data = std::fs::read(&input).with_context(|| format!("không đọc được {}", input.display()))?;
            let profile = XmlProfile::parse(&profile).context("--profile phải là einvoice | enveloped | xades")?;
            let (mut s, hash) = open_signer(&cfg, cli.fast, &common)?;
            let opts = XmlSignOptions { profile, hash, reference_id: ref_id, parent_path: parent, signature_id: sig_id };
            let out = xml::sign_xml(&mut s, &data, &opts)?;
            std::fs::write(&output, out)?;
            println!("Đã ký XML ({profile:?}) → {}", output.display());
        }
        Cmd::Serve { port, allow_origin } => {
            let mut cfg = cfg;
            cfg.agent_allowed_origins.extend(allow_origin);
            let port = port.unwrap_or(cfg.agent_port);
            let origins = cfg.agent_allowed_origins.clone();
            let _h = linuxsign_core::agent::start(cfg, port).map_err(anyhow::Error::msg)?;
            println!("LinuxSign agent: http://127.0.0.1:{port}");
            println!("Origin được phép: {}", if origins.is_empty() { "(chỉ ứng dụng cục bộ)".into() } else { origins.join(", ") });
            loop {
                std::thread::park();
            }
        }
    }
    Ok(())
}
