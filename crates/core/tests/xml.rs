//! Kiểm thử ký XML. Đối chiếu độc lập bằng libxml2:
//!   - C14N của ta == `xmllint --c14n`
//!   - Chữ ký được `xmlsec1 --verify` chấp nhận; sửa dữ liệu thì bị từ chối.
//! Biến XMLSEC1 / XMLLINT trỏ tới công cụ nếu không nằm trong PATH; thiếu thì bỏ qua phần đối chiếu.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use linuxsign_core::certinfo;
use linuxsign_core::signer::{BackendError, Mech, SignBackend, Signer};
use linuxsign_core::xml::{self, XmlProfile, XmlSignOptions};
use rsa::pkcs8::DecodePrivateKey;
use std::path::{Path, PathBuf};
use std::process::Command;

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

struct SoftRsa(rsa::RsaPrivateKey);
impl SignBackend for SoftRsa {
    fn sign(&mut self, mech: Mech, payload: &[u8]) -> Result<Vec<u8>, BackendError> {
        match mech {
            Mech::RsaPkcs => self.0.sign(rsa::Pkcs1v15Sign::new_unprefixed(), payload).map_err(|e| BackendError::Other(e.to_string())),
            _ => Err(BackendError::Unsupported("x".into())),
        }
    }
    fn module(&self) -> String {
        "soft".into()
    }
}

fn signer() -> Signer {
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(&std::fs::read_to_string(format!("{FIX}/rsa_key.pem")).unwrap()).unwrap();
    let cert = certinfo::parse(&std::fs::read(format!("{FIX}/rsa_cert.der")).unwrap(), &[1], "t").unwrap();
    Signer::with_backend(Box::new(SoftRsa(key)), cert, vec![])
}

fn tool(env: &str, name: &str) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(env) {
        return Some(PathBuf::from(p));
    }
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(name)).find(|f| f.is_file()))
}

fn out_dir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("xml");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn cert_pem(dir: &Path) -> PathBuf {
    let der = std::fs::read(format!("{FIX}/rsa_cert.der")).unwrap();
    let b64 = B64.encode(der);
    let body: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    let p = dir.join("cert.pem");
    std::fs::write(&p, format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", body.join("\n"))).unwrap();
    p
}

/// Chạy xmlsec1 --verify. Trả về None nếu không có xmlsec1.
fn xmlsec_verify(file: &Path, id_attrs: &[&str]) -> Option<(bool, String)> {
    let bin = tool("XMLSEC1", "xmlsec1")?;
    let dir = out_dir();
    let mut cmd = Command::new(bin);
    cmd.arg("--verify").arg("--trusted-pem").arg(cert_pem(&dir)).args(["--enabled-reference-uris", "empty,same-doc"]);
    for a in id_attrs {
        let (attr, node) = a.split_once(' ').unwrap();
        cmd.arg(format!("--id-attr:{attr}")).arg(node);
    }
    let o = cmd.arg(file).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    Some((o.status.success() && text.contains("OK"), text))
}

// ----------------------------------------------------------------------------- C14N

const TRICKY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<?xml-stylesheet href=\"a.xsl\"   type=\"text/xsl\"?>\r\n\
<!-- chú thích đầu -->\r\n\
<doc xmlns=\"urn:a\" xmlns:b=\"urn:b\" z=\"1\" b:y='2' a=\"x&#9;y\nz\" xml:lang=\"vi\">\r\n\
  <b:e1   b:c=\"3\" xmlns:b=\"urn:b\" xmlns:unused=\"urn:u\"/>\r\n\
  <e2 xmlns=\"\"><e3 xmlns=\"urn:c\">Tiếng Việt &amp; &lt;tag&gt; &#x1EA0; \"q\" 'a'</e3></e2>\r\n\
  <![CDATA[ <raw> & ]]><!-- bỏ -->\r\n\
  <e4 attr=\"&lt;&quot;&gt;&apos;\"><?pi   dữ liệu ?></e4>\r\n\
</doc>\r\n\
<!-- cuối -->\r\n";

#[test]
fn c14n_matches_libxml2() {
    let doc = xml::parse(&xml::normalize_newlines(TRICKY)).unwrap();
    let ours = doc.c14n_with_comments(None, None);
    // Bản không comment (dùng cho XMLDSig) = bản có comment bỏ đi các comment
    let no_comments = doc.c14n(None, None);
    assert!(!no_comments.contains("<!--"));
    assert_eq!(
        no_comments,
        ours.replace("<!-- chú thích đầu -->\n", "").replace("<!-- bỏ -->", "").replace("\n<!-- cuối -->", "")
    );
    let Some(xmllint) = tool("XMLLINT", "xmllint") else {
        eprintln!("bỏ qua: không có xmllint");
        return;
    };
    let p = out_dir().join("tricky.xml");
    std::fs::write(&p, TRICKY).unwrap();
    let o = Command::new(xmllint).arg("--c14n").arg(&p).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(ours, String::from_utf8(o.stdout).unwrap());
}

// ----------------------------------------------------------------------------- Hóa đơn điện tử

const INVOICE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<HDon>
  <DLHDon Id="data">
    <TTChung><PBan>2.0.1</PBan><THDon>Hóa đơn giá trị gia tăng</THDon><KHMSHDon>1</KHMSHDon><KHHDon>C26TAA</KHHDon><SHDon>123</SHDon><NLap>2026-11-16</NLap><DVTTe>VND</DVTTe></TTChung>
    <NDHDon>
      <NBan><Ten>CÔNG TY TNHH THỬ NGHIỆM</Ten><MST>0101234567</MST><DChi>Số 1 &amp; 2, Hà Nội</DChi></NBan>
      <NMua><Ten>Công ty B</Ten><MST>0109999999</MST></NMua>
      <DSHHDVu><HHDVu><TChat>1</TChat><STT>1</STT><THHDVu>Dịch vụ &lt;tư vấn&gt;</THHDVu><ThTien>1000000</ThTien></HHDVu></DSHHDVu>
      <TToan><TgTCThue>1000000</TgTCThue><TgTThue>100000</TgTThue><TgTTTBSo>1100000</TgTTTBSo><TgTTTBChu>Một triệu một trăm nghìn đồng</TgTTTBChu></TToan>
    </NDHDon>
  </DLHDon>
  <DSCKS><NBan/><NMua/></DSCKS>
</HDon>
"#;

const ID_ATTRS_EINVOICE: &[&str] = &["Id DLHDon", "Id http://www.w3.org/2000/09/xmldsig#:SignatureProperty"];

#[test]
fn einvoice_vn_signature_verifies_with_xmlsec1() {
    let out = xml::sign_xml(&mut signer(), INVOICE.as_bytes(), &XmlSignOptions::new(XmlProfile::EInvoiceVn)).unwrap();
    let s = String::from_utf8(out.clone()).unwrap();
    assert!(s.contains("<DSCKS><NBan><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\""), "chữ ký phải nằm trong DSCKS/NBan");
    assert!(s.contains("<Reference URI=\"#data\">") && s.contains("<SigningTime>"));
    assert!(s.starts_with(&INVOICE[..INVOICE.find("<DSCKS>").unwrap()]), "phần dữ liệu gốc giữ nguyên từng byte");
    let p = out_dir().join("hoadon_signed.xml");
    std::fs::write(&p, &out).unwrap();
    if let Some((ok, log)) = xmlsec_verify(&p, ID_ATTRS_EINVOICE) {
        assert!(ok, "xmlsec1 không chấp nhận:\n{log}");
    }

    // Sửa 1 ký tự trong dữ liệu hóa đơn → phải bị phát hiện
    let tampered = s.replace("<ThTien>1000000</ThTien>", "<ThTien>9000000</ThTien>");
    let p2 = out_dir().join("hoadon_tampered.xml");
    std::fs::write(&p2, tampered).unwrap();
    if let Some((ok, log)) = xmlsec_verify(&p2, ID_ATTRS_EINVOICE) {
        assert!(!ok, "xmlsec1 phải từ chối văn bản bị sửa:\n{log}");
    }
}

#[test]
fn einvoice_creates_missing_dscks() {
    let src = INVOICE.replace("  <DSCKS><NBan/><NMua/></DSCKS>\n", "");
    let out = xml::sign_xml(&mut signer(), src.as_bytes(), &XmlSignOptions::new(XmlProfile::EInvoiceVn)).unwrap();
    let p = out_dir().join("hoadon_no_dscks.xml");
    std::fs::write(&p, &out).unwrap();
    assert!(String::from_utf8_lossy(&out).contains("<DSCKS><NBan><Signature"));
    if let Some((ok, log)) = xmlsec_verify(&p, ID_ATTRS_EINVOICE) {
        assert!(ok, "{log}");
    }
}

// ----------------------------------------------------------------------------- Tờ khai có namespace

const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<HSoThueDTu xmlns=\"http://kekhaithue.gdt.gov.vn/TKhaiThue\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\r\n\
  <HSoKhaiThue id=\"_NODE_TO_SIGN\">\r\n\
    <TTinChung><TTinTKhaiThue><TKhaiThue><maTKhai>842</maTKhai><tenTKhai>Tờ khai thuế GTGT</tenTKhai></TKhaiThue>\
    <NNT><mst>0101234567</mst><tenNNT>CÔNG TY TNHH THỬ NGHIỆM</tenNNT></NNT></TTinTKhaiThue></TTinChung>\r\n\
    <CTieuTKhaiChinh><ct21 xsi:nil=\"true\"/><ct22>1100000</ct22></CTieuTKhaiChinh>\r\n\
  </HSoKhaiThue>\r\n\
  <CKyDTu/>\r\n\
</HSoThueDTu>\r\n";

#[test]
fn namespaced_declaration_with_id_reference() {
    let mut opts = XmlSignOptions::new(XmlProfile::Enveloped);
    opts.reference_id = Some("_NODE_TO_SIGN".into());
    opts.parent_path = Some("CKyDTu".into());
    let out = xml::sign_xml(&mut signer(), DECLARATION.as_bytes(), &opts).unwrap();
    let p = out_dir().join("tokhai_signed.xml");
    std::fs::write(&p, &out).unwrap();
    assert!(String::from_utf8_lossy(&out).contains("<CKyDTu><Signature"));
    if let Some((ok, log)) = xmlsec_verify(&p, &["id http://kekhaithue.gdt.gov.vn/TKhaiThue:HSoKhaiThue"]) {
        assert!(ok, "{log}");
    }
}

#[test]
fn enveloped_whole_document() {
    let out = xml::sign_xml(&mut signer(), DECLARATION.as_bytes(), &XmlSignOptions::new(XmlProfile::Enveloped)).unwrap();
    let p = out_dir().join("enveloped.xml");
    std::fs::write(&p, &out).unwrap();
    if let Some((ok, log)) = xmlsec_verify(&p, &[]) {
        assert!(ok, "{log}");
    }
}

// ----------------------------------------------------------------------------- XAdES

#[test]
fn xades_bes_verifies_and_has_qualifying_properties() {
    let out = xml::sign_xml(&mut signer(), TRICKY.as_bytes(), &XmlSignOptions::new(XmlProfile::Xades)).unwrap();
    let s = String::from_utf8(out.clone()).unwrap();
    for needle in ["xades:QualifyingProperties", "xades:SigningTime", "xades:CertDigest", "http://uri.etsi.org/01903#SignedProperties"] {
        assert!(s.contains(needle), "thiếu {needle}");
    }
    let p = out_dir().join("xades.xml");
    std::fs::write(&p, &out).unwrap();
    if let Some((ok, log)) = xmlsec_verify(&p, &["Id http://uri.etsi.org/01903/v1.3.2#:SignedProperties"]) {
        assert!(ok, "{log}");
    }
    assert_eq!(xml::count_signatures(&out), 1);
}

#[test]
fn rejects_entity_declarations_and_missing_reference() {
    let evil = "<!DOCTYPE d [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><d>&x;</d>";
    assert!(xml::sign_xml(&mut signer(), evil.as_bytes(), &XmlSignOptions::new(XmlProfile::Enveloped)).is_err());
    let mut opts = XmlSignOptions::new(XmlProfile::Enveloped);
    opts.reference_id = Some("khong-co".into());
    assert!(xml::sign_xml(&mut signer(), INVOICE.as_bytes(), &opts).is_err());
}
