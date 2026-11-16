//! Ký XML: XMLDSig enveloped, hồ sơ hóa đơn điện tử Việt Nam, và XAdES-BES.
//!
//! - Chuẩn hóa: Canonical XML 1.0 (inclusive, không comment), hiện thực trong file này
//!   và được đối chiếu với libxml2 (`xmllint --c14n`, `xmlsec1`) trong kiểm thử.
//! - Chữ ký được chèn trực tiếp vào văn bản gốc (giữ nguyên định dạng của file).
//! - Ba hồ sơ:
//!   * `enveloped`: URI="" (toàn văn bản), chữ ký là con cuối của phần tử gốc (tờ khai, hồ sơ...)
//!   * `einvoice_vn`: tham chiếu phần dữ liệu hóa đơn (`<DLHDon Id="...">`), chữ ký đặt trong
//!     `DSCKS/NBan`, kèm SignatureProperty `SigningTime` (thời điểm ký) theo kiểu hóa đơn điện tử VN.
//!   * `xades`: XAdES-BES (QualifyingProperties/SignedProperties: SigningTime, SigningCertificate).
//! Đường dẫn chèn, Id tham chiếu, Id chữ ký đều chỉnh được để khớp đặc tả của từng hệ thống.

use crate::certinfo;
use crate::der;
use crate::signer::{HashAlg, SignError, Signer};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quick_xml::events::Event;
use std::collections::BTreeMap;

pub const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const NS_XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const ALG_C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const ALG_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";

#[derive(Debug, thiserror::Error)]
pub enum XmlError {
    #[error("XML không hợp lệ: {0}")]
    Parse(String),
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Sign(#[from] SignError),
}

// ============================================================================
// Cây XML tối giản, giữ nguyên tên có tiền tố và vị trí byte để chèn chữ ký
// ============================================================================

#[derive(Debug, Clone)]
pub enum Node {
    Elem(usize),
    Text(String),
    Pi(String),
    Comment(String),
}

#[derive(Debug, Clone)]
pub struct Elem {
    pub qname: String,
    /// Thuộc tính theo thứ tự gốc, giá trị đã giải mã (kể cả xmlns)
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
    pub parent: Option<usize>,
    /// Vị trí byte: đầu thẻ mở, cuối thẻ mở, đầu thẻ đóng (với <a/> = đầu thẻ), cuối phần tử
    pub start: usize,
    pub start_end: usize,
    pub end_tag_start: usize,
    pub empty: bool,
}

impl Elem {
    pub fn local_name(&self) -> &str {
        self.qname.rsplit(':').next().unwrap_or(&self.qname)
    }
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct XmlDoc {
    pub elems: Vec<Elem>,
    pub root: usize,
    pub prolog: Vec<Node>,
    pub epilog: Vec<Node>,
}

/// Chuẩn hóa xuống dòng như bộ phân tích XML (CRLF/CR → LF).
pub fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn unescape(raw: &str) -> Result<String, XmlError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let j = rest[i..].find(';').ok_or_else(|| XmlError::Parse("thiếu ';' sau '&'".into()))? + i;
        out.push(resolve_ref(&rest[i + 1..j])?);
        rest = &rest[j + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve_ref(name: &str) -> Result<char, XmlError> {
    let bad = || XmlError::Parse(format!("thực thể không hỗ trợ: &{name};"));
    Ok(match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "quot" => '"',
        "apos" => '\'',
        n if n.starts_with("#x") => char::from_u32(u32::from_str_radix(&n[2..], 16).map_err(|_| bad())?).ok_or_else(bad)?,
        n if n.starts_with('#') => char::from_u32(n[1..].parse().map_err(|_| bad())?).ok_or_else(bad)?,
        _ => return Err(bad()),
    })
}

pub fn parse(src: &str) -> Result<XmlDoc, XmlError> {
    let mut reader = quick_xml::Reader::from_str(src);
    reader.config_mut().trim_text(false);
    reader.config_mut().expand_empty_elements = false;
    reader.config_mut().check_end_names = true;
    let perr = |e: quick_xml::Error| XmlError::Parse(e.to_string());

    let mut elems: Vec<Elem> = vec![];
    let mut stack: Vec<usize> = vec![];
    let (mut prolog, mut epilog, mut root) = (vec![], vec![], None);
    let mut text = String::new();

    fn flush(text: &mut String, stack: &[usize], elems: &mut [Elem]) {
        if !text.is_empty() {
            if let Some(&p) = stack.last() {
                elems[p].children.push(Node::Text(std::mem::take(text)));
            } else {
                text.clear(); // khoảng trắng ngoài phần tử gốc: bỏ
            }
        }
    }

    loop {
        let before = reader.buffer_position() as usize;
        let ev = reader.read_event().map_err(perr)?;
        let after = reader.buffer_position() as usize;
        match ev {
            Event::Text(t) => text.push_str(&unescape(&String::from_utf8_lossy(&t))?),
            Event::GeneralRef(r) => text.push(resolve_ref(&String::from_utf8_lossy(&r))?),
            Event::CData(c) => text.push_str(&String::from_utf8_lossy(&c)),
            ev @ (Event::Start(_) | Event::Empty(_)) => {
                flush(&mut text, &stack, &mut elems);
                let (e, empty) = match &ev {
                    Event::Start(e) => (e, false),
                    Event::Empty(e) => (e, true),
                    _ => unreachable!(),
                };
                let qname = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let mut attrs = vec![];
                for a in e.attributes() {
                    let a = a.map_err(|e| XmlError::Parse(e.to_string()))?;
                    // Chuẩn hóa giá trị thuộc tính (XML 1.0 §3.3.3): tab/xuống dòng → khoảng trắng
                    let raw = String::from_utf8_lossy(&a.value).replace(['\t', '\n'], " ");
                    attrs.push((String::from_utf8_lossy(a.key.as_ref()).to_string(), unescape(&raw)?));
                }
                let id = elems.len();
                let parent = stack.last().copied();
                elems.push(Elem {
                    qname, attrs, children: vec![], parent, start: before, start_end: after,
                    end_tag_start: if empty { before } else { 0 }, empty,
                });
                match parent {
                    Some(p) => elems[p].children.push(Node::Elem(id)),
                    None if root.is_none() => root = Some(id),
                    None => return Err(XmlError::Parse("có nhiều hơn một phần tử gốc".into())),
                }
                if !empty {
                    stack.push(id);
                }
            }
            Event::End(_) => {
                flush(&mut text, &stack, &mut elems);
                let id = stack.pop().ok_or_else(|| XmlError::Parse("thẻ đóng thừa".into()))?;
                elems[id].end_tag_start = before;
            }
            Event::PI(p) => {
                flush(&mut text, &stack, &mut elems);
                let node = Node::Pi(String::from_utf8_lossy(&p).to_string());
                match (stack.last(), root) {
                    (Some(&e), _) => elems[e].children.push(node),
                    (None, None) => prolog.push(node),
                    (None, Some(_)) => epilog.push(node),
                }
            }
            Event::Comment(c) => {
                flush(&mut text, &stack, &mut elems);
                let node = Node::Comment(String::from_utf8_lossy(&c).to_string());
                match (stack.last(), root) {
                    (Some(&e), _) => elems[e].children.push(node),
                    (None, None) => prolog.push(node),
                    (None, Some(_)) => epilog.push(node),
                }
            }
            Event::Decl(d) => {
                if let Some(Ok(enc)) = d.encoding() {
                    let enc = String::from_utf8_lossy(&enc).to_ascii_lowercase();
                    if enc != "utf-8" && enc != "utf8" && enc != "us-ascii" {
                        return Err(XmlError::Invalid(format!("Chỉ hỗ trợ XML mã hóa UTF-8 (file khai báo {enc}).")));
                    }
                }
            }
            Event::DocType(d) => {
                if String::from_utf8_lossy(&d).contains("<!ENTITY") {
                    return Err(XmlError::Invalid("XML có khai báo ENTITY trong DOCTYPE: không hỗ trợ (rủi ro bảo mật).".into()));
                }
            }
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(XmlError::Parse("thiếu thẻ đóng".into()));
    }
    Ok(XmlDoc { elems, root: root.ok_or_else(|| XmlError::Parse("không có phần tử gốc".into()))?, prolog, epilog })
}

// ============================================================================
// Canonical XML 1.0 (inclusive, không comment)
// ============================================================================

fn esc_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn esc_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn pi(data: &str, out: &mut String) {
    let (target, rest) = data.split_once(char::is_whitespace).unwrap_or((data, ""));
    let rest = rest.trim_start();
    out.push_str("<?");
    out.push_str(target);
    if !rest.is_empty() {
        out.push(' ');
        out.push_str(rest);
    }
    out.push_str("?>");
}

fn comment(c: &str, out: &mut String) {
    out.push_str("<!--");
    out.push_str(c);
    out.push_str("-->");
}

type NsMap = BTreeMap<String, String>;

impl XmlDoc {
    fn ns_decls(&self, id: usize) -> impl Iterator<Item = (String, String)> + '_ {
        self.elems[id].attrs.iter().filter_map(|(k, v)| {
            if k == "xmlns" {
                Some((String::new(), v.clone()))
            } else {
                k.strip_prefix("xmlns:").map(|p| (p.to_string(), v.clone()))
            }
        })
    }

    /// Không gian tên và thuộc tính xml:* hiệu lực tại phần tử cha của `id`.
    fn context(&self, id: usize) -> (NsMap, Vec<(String, String)>) {
        let mut chain = vec![];
        let mut cur = self.elems[id].parent;
        while let Some(p) = cur {
            chain.push(p);
            cur = self.elems[p].parent;
        }
        let mut ns = NsMap::new();
        let mut xml_attrs: Vec<(String, String)> = vec![];
        for &p in chain.iter().rev() {
            ns.extend(self.ns_decls(p));
            for (k, v) in &self.elems[p].attrs {
                if k.starts_with("xml:") {
                    xml_attrs.retain(|(x, _)| x != k);
                    xml_attrs.push((k.clone(), v.clone()));
                }
            }
        }
        (ns, xml_attrs)
    }

    /// C14N của phần tử `apex` (None = toàn văn bản), loại trừ cây con `exclude`
    /// (dùng cho phép biến đổi enveloped-signature).
    pub fn c14n(&self, apex: Option<usize>, exclude: Option<usize>) -> String {
        self.c14n_impl(apex, exclude, false)
    }

    /// Canonical XML 1.0 có giữ comment (#WithComments).
    pub fn c14n_with_comments(&self, apex: Option<usize>, exclude: Option<usize>) -> String {
        self.c14n_impl(apex, exclude, true)
    }

    fn c14n_impl(&self, apex: Option<usize>, exclude: Option<usize>, comments: bool) -> String {
        let mut out = String::new();
        match apex {
            None => {
                for n in &self.prolog {
                    match n {
                        Node::Pi(p) => pi(p, &mut out),
                        Node::Comment(c) if comments => comment(c, &mut out),
                        _ => continue,
                    }
                    out.push('\n');
                }
                self.render(self.root, &NsMap::new(), &NsMap::new(), &[], exclude, comments, &mut out);
                for n in &self.epilog {
                    match n {
                        Node::Pi(p) => {
                            out.push('\n');
                            pi(p, &mut out);
                        }
                        Node::Comment(c) if comments => {
                            out.push('\n');
                            comment(c, &mut out);
                        }
                        _ => {}
                    }
                }
            }
            Some(a) => {
                let (ctx, xml_attrs) = self.context(a);
                // Phần tử đỉnh không có tổ tiên được xuất → mọi namespace trong phạm vi đều được ghi.
                self.render(a, &ctx, &NsMap::new(), &xml_attrs, exclude, comments, &mut out);
            }
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn render(
        &self,
        id: usize,
        ctx: &NsMap,
        rendered: &NsMap,
        inherit_xml: &[(String, String)],
        exclude: Option<usize>,
        comments: bool,
        out: &mut String,
    ) {
        if Some(id) == exclude {
            return;
        }
        let e = &self.elems[id];
        let mut ns = ctx.clone();
        ns.extend(self.ns_decls(id));

        // Nút namespace cần ghi: khác với phần tử cha đã xuất
        let mut ns_out: Vec<(&str, &str)> = vec![];
        for (p, u) in &ns {
            if p == "xml" {
                continue;
            }
            let parent = rendered.get(p).map(String::as_str).unwrap_or("");
            if p.is_empty() {
                if u != parent {
                    ns_out.push(("", u));
                }
            } else if !u.is_empty() && rendered.get(p) != Some(u) {
                ns_out.push((p, u));
            }
        }
        ns_out.sort_by(|a, b| a.0.cmp(b.0)); // xmlns mặc định ("") đứng đầu

        // Thuộc tính thường + xml:* kế thừa (chỉ ở phần tử đỉnh), sắp theo (namespace URI, tên cục bộ)
        let mut attrs: Vec<(&str, &str)> =
            e.attrs.iter().filter(|(k, _)| k != "xmlns" && !k.starts_with("xmlns:")).map(|(k, v)| (k.as_str(), v.as_str())).collect();
        for (k, v) in inherit_xml {
            if !attrs.iter().any(|(x, _)| x == k) {
                attrs.push((k, v));
            }
        }
        let key = |q: &str| -> (String, String) {
            match q.split_once(':') {
                Some(("xml", l)) => (NS_XML.into(), l.into()),
                Some((p, l)) => (ns.get(p).cloned().unwrap_or_default(), l.into()),
                None => (String::new(), q.into()),
            }
        };
        attrs.sort_by_key(|(k, _)| key(k));

        out.push('<');
        out.push_str(&e.qname);
        for (p, u) in &ns_out {
            out.push_str(if p.is_empty() { " xmlns" } else { " xmlns:" });
            out.push_str(p);
            out.push_str("=\"");
            esc_attr(u, out);
            out.push('"');
        }
        for (k, v) in &attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            esc_attr(v, out);
            out.push('"');
        }
        out.push('>');
        let mut now_rendered = rendered.clone();
        for (p, u) in &ns_out {
            now_rendered.insert(p.to_string(), u.to_string());
        }
        for c in &e.children {
            match c {
                Node::Elem(ch) => self.render(*ch, &ns, &now_rendered, &[], exclude, comments, out),
                Node::Text(t) => esc_text(t, out),
                Node::Pi(p) => pi(p, out),
                Node::Comment(c) if comments => comment(c, out),
                Node::Comment(_) => {}
            }
        }
        out.push_str("</");
        out.push_str(&e.qname);
        out.push('>');
    }

    pub fn find_by_id(&self, id: &str) -> Option<usize> {
        self.elems.iter().position(|e| e.attrs.iter().any(|(k, v)| matches!(k.as_str(), "Id" | "ID" | "id") && v == id))
    }

    pub fn find_child(&self, parent: usize, local: &str) -> Option<usize> {
        self.elems[parent].children.iter().find_map(|c| match c {
            Node::Elem(i) if self.elems[*i].local_name() == local => Some(*i),
            _ => None,
        })
    }

    /// Tiền tố namespace mặc định tại phần tử (để tạo phần tử con cùng namespace).
    fn prefix_of(&self, id: usize) -> Option<&str> {
        self.elems[id].qname.split_once(':').map(|(p, _)| p)
    }
}

// ============================================================================
// Ký
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlProfile {
    /// URI="" + enveloped-signature, chữ ký ở cuối phần tử gốc
    Enveloped,
    /// Hóa đơn điện tử Việt Nam: tham chiếu #Id của DLHDon, chèn vào DSCKS/NBan, kèm SigningTime
    EInvoiceVn,
    /// XAdES-BES enveloped (QualifyingProperties)
    Xades,
}

#[derive(Debug, Clone)]
pub struct XmlSignOptions {
    pub profile: XmlProfile,
    pub hash: HashAlg,
    /// Id phần tử được ký (URI="#id"); None = toàn văn bản, hoặc tự dò với hồ sơ hóa đơn.
    pub reference_id: Option<String>,
    /// Đường dẫn (tính từ phần tử gốc) nơi đặt chữ ký, ví dụ "DSCKS/NBan"; thiếu thì tạo.
    pub parent_path: Option<String>,
    pub signature_id: Option<String>,
}

impl XmlProfile {
    /// "einvoice" | "enveloped" | "xades"
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "einvoice" | "einvoicevn" | "hoadon" | "hddt" => Some(Self::EInvoiceVn),
            "enveloped" | "tokhai" | "xmldsig" => Some(Self::Enveloped),
            "xades" | "xadesbes" => Some(Self::Xades),
            _ => None,
        }
    }
}

impl XmlSignOptions {
    pub fn new(profile: XmlProfile) -> Self {
        Self { profile, hash: HashAlg::Sha256, reference_id: None, parent_path: None, signature_id: None }
    }
}

fn digest_uri(h: HashAlg) -> &'static str {
    match h {
        HashAlg::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
        HashAlg::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        HashAlg::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        HashAlg::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
    }
}

fn signature_uri(key_type: &str, h: HashAlg) -> &'static str {
    match (key_type, h) {
        ("EC", HashAlg::Sha1) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
        ("EC", HashAlg::Sha256) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        ("EC", HashAlg::Sha384) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        ("EC", HashAlg::Sha512) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
        (_, HashAlg::Sha1) => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        (_, HashAlg::Sha256) => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        (_, HashAlg::Sha384) => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        (_, HashAlg::Sha512) => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    }
}

fn x(s: &str) -> String {
    let mut o = String::new();
    esc_attr(s, &mut o);
    o
}

/// Số nguyên không dấu big-endian → chuỗi thập phân (cho X509SerialNumber).
fn be_to_decimal(be: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for &byte in be {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let v = *d as u32 * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    let s: String = digits.iter().rev().map(|d| (b'0' + d) as char).collect();
    let t = s.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}

/// ECDSA trong XMLDSig dùng r||s (độ dài cố định), không phải DER.
fn ecdsa_der_to_raw(der_sig: &[u8], key_bits: usize) -> Vec<u8> {
    let n = key_bits.div_ceil(8);
    let Some((seq, _)) = der::read(der_sig) else { return der_sig.to_vec() };
    let ints = der::children(seq.content);
    let mut out = vec![];
    for i in ints.iter().take(2) {
        let v: Vec<u8> = i.content.iter().copied().skip_while(|b| *b == 0).collect();
        out.extend(std::iter::repeat_n(0u8, n.saturating_sub(v.len())));
        out.extend(v);
    }
    out
}

fn random_id() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    hex::encode(&HashAlg::Sha256.digest(format!("{t}{}", std::process::id()).as_bytes())[..6])
}

/// Ký văn bản XML (UTF-8). Trả về văn bản đã có chữ ký.
pub fn sign_xml(signer: &mut Signer, input: &[u8], opts: &XmlSignOptions) -> Result<Vec<u8>, XmlError> {
    let src = std::str::from_utf8(input).map_err(|_| XmlError::Invalid("File XML không phải UTF-8.".into()))?;
    let src = normalize_newlines(src.strip_prefix('\u{feff}').unwrap_or(src));
    let doc = parse(&src)?;
    let h = opts.hash;
    let sid = opts.signature_id.clone().unwrap_or_else(|| format!("sig-{}", random_id()));
    if doc.find_by_id(&sid).is_some() {
        return Err(XmlError::Invalid(format!("Id \"{sid}\" đã tồn tại trong văn bản.")));
    }

    // ---- Tham chiếu dữ liệu & vị trí chèn theo hồ sơ
    let reference_id = match (opts.profile, &opts.reference_id) {
        (_, Some(id)) => Some(id.clone()),
        (XmlProfile::EInvoiceVn, None) => {
            let dl = doc.find_child(doc.root, "DLHDon").ok_or_else(|| {
                XmlError::Invalid("Không thấy phần tử DLHDon (dữ liệu hóa đơn). Hãy chỉ định Id phần tử cần ký.".into())
            })?;
            Some(doc.elems[dl].attr("Id").map(str::to_string).ok_or_else(|| {
                XmlError::Invalid("Phần tử DLHDon chưa có thuộc tính Id (ví dụ Id=\"data\").".into())
            })?)
        }
        _ => None,
    };
    if let Some(id) = &reference_id {
        if doc.find_by_id(id).is_none() {
            return Err(XmlError::Invalid(format!("Không thấy phần tử có Id=\"{id}\".")));
        }
    }
    let parent_path = opts
        .parent_path
        .clone()
        .or_else(|| (opts.profile == XmlProfile::EInvoiceVn).then(|| "DSCKS/NBan".to_string()))
        .unwrap_or_default();

    // ---- Dựng khối Signature với chỗ trống
    let cert = signer.cert.clone();
    let cert = &cert;
    let parts = certinfo::parts(&cert.der()).map_err(|e| XmlError::Invalid(e.to_string()))?;
    let now = chrono::Local::now();
    let uri = reference_id.as_ref().map(|i| format!("#{i}")).unwrap_or_default();
    let dm = format!("<DigestMethod Algorithm=\"{}\"/>", digest_uri(h));
    let mut refs = format!(
        "<Reference URI=\"{}\"><Transforms><Transform Algorithm=\"{ALG_ENVELOPED}\"/></Transforms>{dm}<DigestValue>@@D0@@</DigestValue></Reference>",
        x(&uri)
    );
    let mut objects = String::new();
    let prop_id = format!("{sid}-SigningTime");
    let sp_id = format!("{sid}-SignedProperties");
    match opts.profile {
        XmlProfile::EInvoiceVn => {
            refs += &format!("<Reference URI=\"#{prop_id}\">{dm}<DigestValue>@@D1@@</DigestValue></Reference>");
            objects += &format!(
                "<Object Id=\"{sid}-Object\"><SignatureProperties><SignatureProperty Id=\"{prop_id}\" Target=\"#{sid}\">\
                 <SigningTime>{}</SigningTime></SignatureProperty></SignatureProperties></Object>",
                now.format("%Y-%m-%dT%H:%M:%S")
            );
        }
        XmlProfile::Xades => {
            refs += &format!(
                "<Reference Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#{sp_id}\">{dm}<DigestValue>@@D1@@</DigestValue></Reference>"
            );
            let cert_digest = B64.encode(h.digest(&cert.der()));
            objects += &format!(
                "<Object><xades:QualifyingProperties xmlns:xades=\"{NS_XADES}\" Target=\"#{sid}\">\
                 <xades:SignedProperties Id=\"{sp_id}\"><xades:SignedSignatureProperties>\
                 <xades:SigningTime>{}</xades:SigningTime>\
                 <xades:SigningCertificate><xades:Cert><xades:CertDigest>{dm}<DigestValue>{cert_digest}</DigestValue></xades:CertDigest>\
                 <xades:IssuerSerial><X509IssuerName>{}</X509IssuerName><X509SerialNumber>{}</X509SerialNumber></xades:IssuerSerial>\
                 </xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties>\
                 </xades:QualifyingProperties></Object>",
                now.to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
                x(&issuer_rfc4514(&cert.der())),
                be_to_decimal(&parts.serial),
            );
        }
        XmlProfile::Enveloped => {}
    }
    let mut certs = format!("<X509Certificate>{}</X509Certificate>", cert.der_b64);
    for c in &signer.chain {
        certs += &format!("<X509Certificate>{}</X509Certificate>", c.der_b64);
    }
    let sig_xml = format!(
        "<Signature xmlns=\"{NS_DSIG}\" Id=\"{sid}\"><SignedInfo><CanonicalizationMethod Algorithm=\"{ALG_C14N}\"/>\
         <SignatureMethod Algorithm=\"{}\"/>{refs}</SignedInfo><SignatureValue>@@SV@@</SignatureValue>\
         <KeyInfo><X509Data><X509SubjectName>{}</X509SubjectName>{certs}</X509Data></KeyInfo>{objects}</Signature>",
        signature_uri(&cert.key_type, h),
        x(&cert.subject),
    );

    // ---- Chèn vào văn bản gốc (không thêm khoảng trắng, để không đổi phần dữ liệu đã ký)
    let mut cur = doc.root;
    let segs: Vec<&str> = parent_path.split('/').filter(|s| !s.is_empty()).collect();
    let mut idx = 0;
    while idx < segs.len() {
        match doc.find_child(cur, segs[idx]) {
            Some(c) => {
                cur = c;
                idx += 1;
            }
            None => break,
        }
    }
    // Các phần tử còn thiếu được tạo cùng tiền tố namespace với phần tử chứa
    let pfx = doc.prefix_of(cur).map(|p| format!("{p}:")).unwrap_or_default();
    let mut wrapped = sig_xml.clone();
    for s in segs[idx..].iter().rev() {
        wrapped = format!("<{pfx}{s}>{wrapped}</{pfx}{s}>");
    }
    let e = &doc.elems[cur];
    let d1 = if e.empty {
        // <NBan/> → <NBan>…</NBan>
        let open = src[e.start..e.start_end].trim_end_matches('>').trim_end().trim_end_matches('/').to_string();
        format!("{}{open}>{wrapped}</{}>{}", &src[..e.start], e.qname, &src[e.start_end..])
    } else {
        format!("{}{wrapped}{}", &src[..e.end_tag_start], &src[e.end_tag_start..])
    };

    // ---- Băm các tham chiếu trên văn bản đã chèn
    let doc1 = parse(&d1)?;
    let sig_el = doc1.find_by_id(&sid).ok_or_else(|| XmlError::Invalid("lỗi chèn chữ ký".into()))?;
    let data_c14n = match &reference_id {
        Some(id) => doc1.c14n(Some(doc1.find_by_id(id).unwrap()), Some(sig_el)),
        None => doc1.c14n(None, Some(sig_el)),
    };
    let mut d2 = d1.replacen("@@D0@@", &B64.encode(h.digest(data_c14n.as_bytes())), 1);
    if opts.profile != XmlProfile::Enveloped {
        let pid = if opts.profile == XmlProfile::Xades { &sp_id } else { &prop_id };
        let p = doc1.find_by_id(pid).expect("thuộc tính ký vừa chèn");
        d2 = d2.replacen("@@D1@@", &B64.encode(h.digest(doc1.c14n(Some(p), None).as_bytes())), 1);
    }

    // ---- Ký SignedInfo đã chuẩn hóa
    let doc2 = parse(&d2)?;
    let sig2 = doc2.find_by_id(&sid).unwrap();
    let si = doc2.find_child(sig2, "SignedInfo").unwrap();
    let si_c14n = doc2.c14n(Some(si), None);
    let res = signer.sign(Some(si_c14n.as_bytes()), None, h, false)?;
    let sigval = if cert.key_type == "EC" {
        ecdsa_der_to_raw(&res.signature, cert.key_size.unwrap_or(256))
    } else {
        res.signature
    };
    let out = d2.replacen("@@SV@@", &B64.encode(sigval), 1);
    Ok(out.into_bytes())
}

/// Tên tổ chức cấp theo RFC 4514 (thứ tự đảo, như XMLDSig yêu cầu).
fn issuer_rfc4514(cert_der: &[u8]) -> String {
    use x509_parser::prelude::*;
    let Ok((_, c)) = parse_x509_certificate(cert_der) else { return String::new() };
    let mut rdns: Vec<String> = c
        .issuer()
        .iter()
        .map(|rdn| {
            rdn.iter()
                .map(|a| {
                    let oid = a.attr_type().to_id_string();
                    let k = match oid.as_str() {
                        "2.5.4.3" => "CN".to_string(),
                        "2.5.4.10" => "O".into(),
                        "2.5.4.11" => "OU".into(),
                        "2.5.4.7" => "L".into(),
                        "2.5.4.8" => "ST".into(),
                        "2.5.4.6" => "C".into(),
                        "0.9.2342.19200300.100.1.1" => "UID".into(),
                        "1.2.840.113549.1.9.1" => "E".into(),
                        o => o.to_string(),
                    };
                    let v = a.as_str().unwrap_or_default();
                    let v: String = v
                        .chars()
                        .flat_map(|ch| match ch {
                            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => vec!['\\', ch],
                            c => vec![c],
                        })
                        .collect();
                    format!("{k}={v}")
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    rdns.reverse();
    rdns.join(",")
}

/// Đọc nhanh: văn bản có bao nhiêu chữ ký XMLDSig (để giao diện cảnh báo/hiển thị).
pub fn count_signatures(input: &[u8]) -> usize {
    let Ok(s) = std::str::from_utf8(input) else { return 0 };
    parse(&normalize_newlines(s))
        .map(|d| d.elems.iter().filter(|e| e.local_name() == "Signature").count())
        .unwrap_or(0)
}
