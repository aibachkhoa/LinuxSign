//! Kiểm thử toàn bộ luồng ký với "token" phần mềm.
//!
//! Chỉ thay lớp gọi driver (SignBackend); chọn cơ chế, dự phòng, DigestInfo,
//! chuyển ECDSA r||s → DER, xác minh, CMS và PDF đều chạy thật. Kết quả CMS/PDF
//! được kiểm tra chéo bằng công cụ độc lập: `openssl cms -verify` và `pdfsig` (poppler).

use linuxsign_core::certinfo::{self, CertInfo};
use linuxsign_core::cms::{self, CmsOptions};
use linuxsign_core::pdf::{self, PdfSignOptions, VisibleSignature};
use linuxsign_core::signer::{BackendError, HashAlg, Mech, SignBackend, SignError, Signer};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use rsa::pkcs8::DecodePrivateKey;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

enum Key {
    Rsa(rsa::RsaPrivateKey),
    Ec(p256::ecdsa::SigningKey),
}

struct Soft {
    key: Key,
    unsupported: Vec<Mech>,
    calls: Rc<RefCell<Vec<Mech>>>,
}

impl SignBackend for Soft {
    fn sign(&mut self, mech: Mech, payload: &[u8]) -> Result<Vec<u8>, BackendError> {
        self.calls.borrow_mut().push(mech);
        if self.unsupported.contains(&mech) {
            return Err(BackendError::Unsupported("CKR_MECHANISM_INVALID".into()));
        }
        let mut rng = rand::thread_rng();
        let r = match (&self.key, mech) {
            // CKM_RSA_PKCS: đệm PKCS#1 trên đúng payload (DigestInfo) như token làm
            (Key::Rsa(k), Mech::RsaPkcs) => k.sign(rsa::Pkcs1v15Sign::new_unprefixed(), payload),
            (Key::Rsa(k), Mech::RsaPkcsHash(HashAlg::Sha256)) => {
                k.sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &HashAlg::Sha256.digest(payload))
            }
            (Key::Rsa(k), Mech::Pss(HashAlg::Sha256)) => {
                k.sign_with_rng(&mut rng, rsa::Pss::new_with_salt::<sha2::Sha256>(32), payload)
            }
            (Key::Ec(k), Mech::Ecdsa) => {
                let s: p256::ecdsa::Signature = k.sign_prehash(payload).unwrap();
                return Ok(s.to_bytes().to_vec()); // r||s như PKCS#11
            }
            _ => return Err(BackendError::Unsupported("không hỗ trợ".into())),
        };
        r.map_err(|e| BackendError::Other(e.to_string()))
    }
    fn module(&self) -> String {
        "soft".into()
    }
}

fn cert(name: &str) -> CertInfo {
    let der = std::fs::read(format!("{FIX}/{name}_cert.der")).unwrap();
    certinfo::parse(&der, &[1], "test").unwrap()
}

fn rsa_key() -> rsa::RsaPrivateKey {
    rsa::RsaPrivateKey::from_pkcs8_pem(&std::fs::read_to_string(format!("{FIX}/rsa_key.pem")).unwrap()).unwrap()
}

fn signer_with(key: Key, cert_name: &str, unsupported: Vec<Mech>) -> (Signer, Rc<RefCell<Vec<Mech>>>) {
    let calls = Rc::new(RefCell::new(vec![]));
    let s = Signer::with_backend(Box::new(Soft { key, unsupported, calls: calls.clone() }), cert(cert_name), vec![]);
    (s, calls)
}

fn rsa_signer() -> Signer {
    signer_with(Key::Rsa(rsa_key()), "rsa", vec![]).0
}

fn out_dir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("signing");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn tool(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(name)).find(|f| f.is_file()))
}

// ------------------------------ certinfo ------------------------------

#[test]
fn reads_vietnamese_certificate_fields() {
    let c = cert("rsa");
    assert_eq!(c.subject_cn, "CÔNG TY TNHH THỬ NGHIỆM");
    assert_eq!(c.tax_code.as_deref(), Some("0101234567"));
    assert_eq!(c.key_type, "RSA");
    assert_eq!(c.key_size, Some(2048));
    assert!(c.can_sign && !c.is_ca);
    assert!((360..=366).contains(&c.days_left), "days_left = {}", c.days_left);
    assert_eq!(c.status(30), "valid");

    let e = cert("ec");
    assert_eq!(e.subject_cn, "NGUYỄN VĂN A");
    assert_eq!(e.personal_id.as_deref(), Some("CCCD: 001090012345"));
    assert_eq!(e.status(30), "expiring"); // chứng thư 30 ngày → cảnh báo sắp hết hạn
}

// ------------------------------ signer ------------------------------

#[test]
fn rsa_uses_universal_mechanism_first() {
    let mut s = rsa_signer();
    let r = s.sign(Some(b"hoa don so 1"), None, HashAlg::Sha256, false).unwrap();
    assert_eq!(r.mechanism, "CKM_RSA_PKCS");
}

#[test]
fn rsa_falls_back_when_token_rejects_mechanism() {
    let (mut s, calls) = signer_with(Key::Rsa(rsa_key()), "rsa", vec![Mech::RsaPkcs]);
    let r = s.sign(Some(b"abc"), None, HashAlg::Sha256, false).unwrap();
    assert_eq!(r.mechanism, "CKM_SHA256_RSA_PKCS");
    assert_eq!(*calls.borrow(), vec![Mech::RsaPkcs, Mech::RsaPkcsHash(HashAlg::Sha256)]);
}

#[test]
fn rsa_pss() {
    let r = rsa_signer().sign(Some(b"abc"), None, HashAlg::Sha256, true).unwrap();
    assert_eq!(r.mechanism, "CKM_RSA_PKCS_PSS");
}

#[test]
fn ecdsa_signature_is_der_and_verified() {
    let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&std::fs::read_to_string(format!("{FIX}/ec_key.pem")).unwrap()).unwrap();
    let (mut s, _) = signer_with(Key::Ec(key), "ec", vec![]);
    let r = s.sign(Some(b"abc"), None, HashAlg::Sha256, false).unwrap();
    assert_eq!(r.mechanism, "CKM_ECDSA");
    assert_eq!(r.signature[0], 0x30, "phải là DER SEQUENCE");
}

#[test]
fn wrong_key_is_detected() {
    let other = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let (mut s, _) = signer_with(Key::Rsa(other), "rsa", vec![]);
    match s.sign(Some(b"abc"), None, HashAlg::Sha256, false) {
        Err(SignError::Failed(m)) => assert!(m.contains("không khớp"), "{m}"),
        other => panic!("phải báo lỗi sai khóa, nhận {other:?}"),
    }
}

#[test]
fn signs_prehashed_digest() {
    let d = HashAlg::Sha256.digest(b"xyz");
    let r = rsa_signer().sign(None, Some(&d), HashAlg::Sha256, false).unwrap();
    assert_eq!(r.mechanism, "CKM_RSA_PKCS");
}

// ------------------------------ CMS ------------------------------

fn openssl_verify(p7s: &Path, content: Option<&Path>) {
    let Some(openssl) = tool("openssl") else {
        eprintln!("bỏ qua kiểm tra chéo: không có openssl");
        return;
    };
    let mut cmd = Command::new(openssl);
    cmd.args(["cms", "-verify", "-binary", "-inform", "DER", "-noverify", "-out", "/dev/null", "-in"]).arg(p7s);
    if let Some(c) = content {
        cmd.arg("-content").arg(c);
    }
    let o = cmd.output().unwrap();
    assert!(o.status.success(), "openssl cms -verify thất bại: {}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn cms_detached_and_attached_verify_with_openssl() {
    let dir = out_dir();
    let data = "Hợp đồng số 01/2026".as_bytes();
    let content = dir.join("hopdong.txt");
    std::fs::write(&content, data).unwrap();

    let der = cms::sign_data(&mut rsa_signer(), data, &CmsOptions::default()).unwrap();
    std::fs::write(dir.join("hopdong.txt.p7s"), &der).unwrap();
    openssl_verify(&dir.join("hopdong.txt.p7s"), Some(&content));

    let der = cms::sign_data(&mut rsa_signer(), data, &CmsOptions { attached: true, ..Default::default() }).unwrap();
    std::fs::write(dir.join("attached.p7s"), &der).unwrap();
    openssl_verify(&dir.join("attached.p7s"), None);
}

#[test]
fn cms_pss_and_ecdsa_verify_with_openssl() {
    let dir = out_dir();
    let data = b"pss + ecdsa";
    let content = dir.join("d.bin");
    std::fs::write(&content, data).unwrap();
    let der = cms::sign_data(&mut rsa_signer(), data, &CmsOptions { pss: true, ..Default::default() }).unwrap();
    std::fs::write(dir.join("pss.p7s"), &der).unwrap();
    openssl_verify(&dir.join("pss.p7s"), Some(&content));

    let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&std::fs::read_to_string(format!("{FIX}/ec_key.pem")).unwrap()).unwrap();
    let (mut s, _) = signer_with(Key::Ec(key), "ec", vec![]);
    let der = cms::sign_data(&mut s, data, &CmsOptions::default()).unwrap();
    std::fs::write(dir.join("ec.p7s"), &der).unwrap();
    openssl_verify(&dir.join("ec.p7s"), Some(&content));
}

// ------------------------------ PDF ------------------------------

/// PDF tối giản, bảng xref cổ điển.
fn classic_pdf() -> Vec<u8> {
    let content = "BT /F1 24 Tf 72 720 Td (HOP DONG MUA BAN) Tj ET";
    let objs = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".to_string(),
        format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offs = vec![];
    for (i, o) in objs.iter().enumerate() {
        offs.push(out.len());
        out.extend(format!("{} 0 obj\n{o}\nendobj\n", i + 1).bytes());
    }
    let x = out.len();
    out.extend(format!("xref\n0 {}\n0000000000 65535 f\r\n", objs.len() + 1).bytes());
    for o in offs {
        out.extend(format!("{o:010} 00000 n\r\n").bytes());
    }
    out.extend(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n", objs.len() + 1).bytes());
    out
}

/// PDF 1.5 dùng xref stream + object stream (kiểu file Word/LibreOffice xuất ra).
fn xref_stream_pdf() -> Vec<u8> {
    use lopdf::{dictionary, Document, Object, Stream};
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let content = doc.add_object(Stream::new(dictionary! {}, b"BT /F1 24 Tf 72 720 Td (Xref stream) Tj ET".to_vec()));
    let page = doc.add_object(dictionary! {
        "Type" => "Page", "Parent" => pages_id, "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()], "Contents" => content,
    });
    doc.objects.insert(pages_id, Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => vec![page.into()], "Count" => 1 }));
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog);
    doc.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceStream;
    let mut out = vec![];
    doc.save_to(&mut out).unwrap();
    assert!(!out.windows(5).any(|w| w == b"\nxref"), "fixture phải dùng xref stream");
    out
}

fn pdfsig_check(path: &Path, expected: usize) {
    let Some(pdfsig) = tool("pdfsig") else {
        eprintln!("bỏ qua kiểm tra chéo: không có pdfsig");
        return;
    };
    let o = Command::new(pdfsig).arg(path).output().unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    let valid = text.matches("Signature Validation: Signature is Valid.").count();
    assert_eq!(valid, expected, "pdfsig:\n{text}\n{}", String::from_utf8_lossy(&o.stderr));
    assert!(text.contains("ETSI.CAdES.detached"), "{text}");
    assert!(text.contains("Total document signed"), "chữ ký cuối phải phủ toàn bộ file:\n{text}");
}

fn sign_twice(input: Vec<u8>, name: &str) {
    let dir = out_dir();
    let opts1 = PdfSignOptions { reason: Some("Phê duyệt".into()), location: Some("Hà Nội".into()), ..Default::default() };
    let (one, f1) = pdf::sign_pdf(&mut rsa_signer(), &input, &opts1).unwrap();
    assert_eq!(f1, "Signature1");
    assert!(one.starts_with(&input), "incremental update phải giữ nguyên file gốc");
    std::fs::write(dir.join(format!("{name}_1.pdf")), &one).unwrap();
    pdfsig_check(&dir.join(format!("{name}_1.pdf")), 1);

    let opts2 = PdfSignOptions {
        reason: Some("Đồng ý ký kết".into()),
        visible: Some(VisibleSignature { page: 1, rect: [330.0, 60.0, 560.0, 140.0] }),
        ..Default::default()
    };
    let (two, f2) = pdf::sign_pdf(&mut rsa_signer(), &one, &opts2).unwrap();
    assert_eq!(f2, "Signature2");
    assert!(two.starts_with(&one), "chữ ký thứ hai không được phá chữ ký thứ nhất");
    std::fs::write(dir.join(format!("{name}_2.pdf")), &two).unwrap();
    pdfsig_check(&dir.join(format!("{name}_2.pdf")), 2);
}

#[test]
fn pdf_classic_xref_two_signatures() {
    sign_twice(classic_pdf(), "classic");
}

#[test]
fn pdf_xref_stream_two_signatures() {
    sign_twice(xref_stream_pdf(), "xrefstream");
}

#[test]
fn pdf_rejects_missing_page() {
    let opts = PdfSignOptions { visible: Some(VisibleSignature { page: 9, rect: [0.0, 0.0, 10.0, 10.0] }), ..Default::default() };
    assert!(matches!(pdf::sign_pdf(&mut rsa_signer(), &classic_pdf(), &opts), Err(pdf::PdfError::NoPage(9))));
}

#[test]
fn embedded_font_covers_vietnamese() {
    use linuxsign_core::font::{Font, DEFAULT_FONT};
    let text = "Ký bởi: NGUYỄN VĂN ĐỨC – Lý do: Đồng ý phê duyệt hợp đồng. Ỹ ỵ Ơ ư";
    let f = Font::parse(DEFAULT_FONT).unwrap();
    let emb = f.embed(&[text.to_string()]).unwrap();
    // Mọi ký tự (trừ khoảng trắng) đều có glyph thật, không rơi về '?' hay .notdef
    for c in text.chars().filter(|c| !c.is_whitespace()) {
        assert!(emb.to_unicode.values().any(|x| *x == c), "thiếu glyph cho {c:?}");
    }
    assert!(!emb.to_unicode.contains_key(&0), ".notdef không được dùng cho chữ");
    assert!(emb.font_file.len() < 40_000, "subset quá lớn: {} byte", emb.font_file.len());
    assert!(emb.base_name.ends_with("+NotoSans-Regular"), "{}", emb.base_name);
    let cmap = String::from_utf8(emb.to_unicode_cmap()).unwrap();
    assert!(cmap.contains("<1EE8>"), "ToUnicode phải có Ứ (U+1EE8)");
    // Ngắt dòng
    let lines = f.wrap(text, 10.0, 120.0);
    assert!(lines.len() > 2 && lines.iter().all(|l| f.measure(l, 10.0) <= 120.0 || !l.contains(' ')));
}

/// Cần mạng: `cargo test -p linuxsign-core -- --ignored tsa`
#[test]
#[ignore]
fn tsa_live_pdf_with_timestamp() {
    let opts = PdfSignOptions { tsa_url: Some("http://timestamp.digicert.com".into()), ..Default::default() };
    let (out, _) = pdf::sign_pdf(&mut rsa_signer(), &classic_pdf(), &opts).unwrap();
    let p = out_dir().join("tsa.pdf");
    std::fs::write(&p, &out).unwrap();
    pdfsig_check(&p, 1);
}

#[test]
fn reads_page_sizes_for_signature_placement() {
    assert_eq!(pdf::page_sizes(&classic_pdf()).unwrap(), vec![(595.0, 842.0)]);
    assert_eq!(pdf::page_sizes(&xref_stream_pdf()).unwrap(), vec![(595.0, 842.0)]);
}
