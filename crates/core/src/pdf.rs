//! Ký PDF chuẩn PAdES (ETSI.CAdES.detached) bằng incremental update.
//!
//! File gốc được giữ nguyên từng byte; chữ ký mới được nối vào cuối, nên các chữ
//! ký có sẵn không bị phá. Hỗ trợ cả PDF dùng bảng xref cổ điển lẫn xref stream.

use crate::cms::{self, CmsOptions};
use crate::font::{EmbeddedFont, Font, DEFAULT_FONT};
use crate::signer::{HashAlg, SignError, Signer};
use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct VisibleSignature {
    /// Trang (bắt đầu từ 1).
    pub page: u32,
    /// [x1, y1, x2, y2] theo điểm PDF (1/72 inch), gốc tọa độ ở góc dưới trái.
    pub rect: [f32; 4],
}

#[derive(Debug, Clone)]
pub struct PdfSignOptions {
    pub reason: Option<String>,
    pub location: Option<String>,
    pub contact: Option<String>,
    pub hash: HashAlg,
    pub pss: bool,
    pub tsa_url: Option<String>,
    pub visible: Option<VisibleSignature>,
    /// Font TrueType cho khung chữ ký; None = Noto Sans đi kèm (có đủ tiếng Việt).
    pub font: Option<Vec<u8>>,
}

impl Default for PdfSignOptions {
    fn default() -> Self {
        Self { reason: None, location: None, contact: None, hash: HashAlg::Sha256, pss: false, tsa_url: None, visible: None, font: None }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    #[error("Không đọc được PDF: {0}")]
    Parse(String),
    #[error("PDF đã được mã hóa (đặt mật khẩu), cần gỡ mật khẩu trước khi ký.")]
    Encrypted,
    #[error("PDF không có trang {0}")]
    NoPage(u32),
    #[error("Chữ ký lớn hơn vùng dành sẵn ({0} > {1} byte)")]
    TooLarge(usize, usize),
    #[error(transparent)]
    Sign(#[from] SignError),
}

// ----------------------------- Ghi đối tượng PDF -----------------------------

fn write_name(out: &mut Vec<u8>, name: &[u8]) {
    out.push(b'/');
    for &b in name {
        if (0x21..=0x7E).contains(&b) && !b"#()<>[]{}/%".contains(&b) {
            out.push(b);
        } else {
            out.extend(format!("#{b:02X}").bytes());
        }
    }
}

fn write_literal(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'(');
    for &b in s {
        match b {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            b'\r' => out.extend(b"\\r"),
            b'\n' => out.extend(b"\\n"),
            _ => out.push(b),
        }
    }
    out.push(b')');
}

pub fn write_object(out: &mut Vec<u8>, o: &Object) {
    match o {
        Object::Null => out.extend(b"null"),
        Object::Boolean(b) => out.extend(if *b { &b"true"[..] } else { &b"false"[..] }),
        Object::Integer(i) => out.extend(i.to_string().bytes()),
        Object::Real(r) => out.extend(fmt_num(*r).bytes()),
        Object::Name(n) => write_name(out, n),
        Object::String(s, StringFormat::Literal) => write_literal(out, s),
        Object::String(s, StringFormat::Hexadecimal) => out.extend(format!("<{}>", hex::encode(s)).bytes()),
        Object::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_object(out, x);
            }
            out.push(b']');
        }
        Object::Dictionary(d) => write_dict(out, d),
        Object::Stream(s) => {
            let mut d = s.dict.clone();
            d.set("Length", Object::Integer(s.content.len() as i64));
            write_dict(out, &d);
            out.extend(b"\nstream\n");
            out.extend(&s.content);
            out.extend(b"\nendstream");
        }
        Object::Reference((id, gen)) => out.extend(format!("{id} {gen} R").bytes()),
    }
}

fn write_dict(out: &mut Vec<u8>, d: &Dictionary) {
    out.extend(b"<<");
    for (k, v) in d.iter() {
        out.push(b' ');
        write_name(out, k);
        out.push(b' ');
        write_object(out, v);
    }
    out.extend(b" >>");
}

fn fmt_num(x: f32) -> String {
    let s = format!("{x:.3}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() || s == "-0" { "0".into() } else { s.into() }
}

/// Chuỗi văn bản PDF: ASCII → literal; có dấu tiếng Việt → UTF-16BE kèm BOM.
pub fn text_string(s: &str) -> Object {
    if s.bytes().all(|b| (0x20..0x7F).contains(&b)) {
        Object::String(s.as_bytes().to_vec(), StringFormat::Literal)
    } else {
        let mut v = vec![0xFE, 0xFF];
        for u in s.encode_utf16() {
            v.extend(u.to_be_bytes());
        }
        Object::String(v, StringFormat::Hexadecimal)
    }
}


// ----------------------------- Ký -----------------------------

fn resolve<'a>(doc: &'a Document, o: &'a Object) -> &'a Object {
    match o {
        Object::Reference(id) => doc.get_object(*id).unwrap_or(o),
        _ => o,
    }
}

fn last_startxref(buf: &[u8]) -> Option<usize> {
    let pos = buf.windows(9).rposition(|w| w == b"startxref")?;
    let tail = std::str::from_utf8(&buf[pos + 9..(pos + 40).min(buf.len())]).ok()?;
    tail.split_whitespace().next()?.parse().ok()
}

/// Nội dung khung chữ ký: viền + các dòng thông tin, bằng font nhúng có tiếng Việt.
/// Cỡ chữ tự co (11 → 4pt) và tự ngắt dòng cho vừa khung.
fn appearance(
    signer: &Signer,
    opts: &PdfSignOptions,
    w: f32,
    h: f32,
    now: &chrono::DateTime<chrono::Local>,
) -> Result<(Vec<u8>, EmbeddedFont), PdfError> {
    let data = opts.font.as_deref().unwrap_or(DEFAULT_FONT);
    let font = Font::parse(data).map_err(|e| PdfError::Parse(e.to_string()))?;
    let mut items = vec![format!("Ký bởi: {}", signer.cert.subject_cn)];
    if let Some(o) = signer.cert.subject_o.as_deref().filter(|o| !signer.cert.subject_cn.contains(o)) {
        items.push(o.to_string());
    }
    items.push(format!("Ngày ký: {}", now.format("%d/%m/%Y %H:%M:%S")));
    if let Some(r) = opts.reason.as_deref().filter(|s| !s.is_empty()) {
        items.push(format!("Lý do: {r}"));
    }
    if let Some(l) = opts.location.as_deref().filter(|s| !s.is_empty()) {
        items.push(format!("Nơi ký: {l}"));
    }
    let pad = 5.0;
    let (mut fs, mut lines) = (11.0f32, vec![]);
    while fs >= 4.0 {
        lines = items.iter().flat_map(|t| font.wrap(t, fs, w - 2.0 * pad)).collect();
        if lines.len() as f32 * fs * 1.22 <= h - 2.0 * pad {
            break;
        }
        fs -= 0.5;
    }
    let emb = font.embed(&lines).map_err(|e| PdfError::Parse(e.to_string()))?;
    let mut c = format!(
        "q 0.06 0.42 0.31 RG 0.8 w 0.4 0.4 {} {} re S Q\nBT /F1 {} Tf\n",
        fmt_num(w - 0.8), fmt_num(h - 0.8), fmt_num(fs)
    );
    let top = h - pad - fs * 0.95;
    for (i, hx) in emb.lines_hex.iter().enumerate() {
        // dòng đầu (người ký) đậm màu hơn
        let color = if i == 0 { "0.05 0.30 0.20" } else { "0.15 0.20 0.18" };
        let y = top - i as f32 * fs * 1.22;
        c += &format!("{color} rg 1 0 0 1 {} {} Tm <{hx}> Tj\n", fmt_num(pad), fmt_num(y));
    }
    c += "ET\n";
    Ok((c.into_bytes(), emb))
}

/// Ghi bộ đối tượng font Type0 (Type0 → CIDFontType2 → FontDescriptor → FontFile2, ToUnicode).
fn font_objects(emb: &EmbeddedFont, ids: [u32; 5]) -> Vec<(u32, Object)> {
    let [type0, cid, desc, file, tounicode] = ids;
    let name = || Object::Name(emb.base_name.as_bytes().to_vec());
    let mut ff = lopdf::Stream::new(
        Dictionary::from_iter([("Length1", Object::Integer(emb.font_file.len() as i64))]),
        emb.font_file.clone(),
    );
    let _ = ff.compress();
    let mut tu = lopdf::Stream::new(Dictionary::new(), emb.to_unicode_cmap());
    let _ = tu.compress();
    let mut w = vec![];
    for (g, adv) in &emb.widths {
        w.push(Object::Integer(*g as i64));
        w.push(Object::Array(vec![Object::Integer(*adv as i64)]));
    }
    let d = |pairs: Vec<(&str, Object)>| Object::Dictionary(Dictionary::from_iter(pairs));
    vec![
        (type0, d(vec![
            ("Type", Object::Name(b"Font".to_vec())),
            ("Subtype", Object::Name(b"Type0".to_vec())),
            ("BaseFont", name()),
            ("Encoding", Object::Name(b"Identity-H".to_vec())),
            ("DescendantFonts", Object::Array(vec![Object::Reference((cid, 0))])),
            ("ToUnicode", Object::Reference((tounicode, 0))),
        ])),
        (cid, d(vec![
            ("Type", Object::Name(b"Font".to_vec())),
            ("Subtype", Object::Name(b"CIDFontType2".to_vec())),
            ("BaseFont", name()),
            ("CIDSystemInfo", d(vec![
                ("Registry", Object::string_literal("Adobe")),
                ("Ordering", Object::string_literal("Identity")),
                ("Supplement", Object::Integer(0)),
            ])),
            ("FontDescriptor", Object::Reference((desc, 0))),
            ("CIDToGIDMap", Object::Name(b"Identity".to_vec())),
            ("DW", Object::Integer(1000)),
            ("W", Object::Array(w)),
        ])),
        (desc, d(vec![
            ("Type", Object::Name(b"FontDescriptor".to_vec())),
            ("FontName", name()),
            ("Flags", Object::Integer(32)),
            ("FontBBox", Object::Array(emb.bbox.iter().map(|v| Object::Integer(*v as i64)).collect())),
            ("ItalicAngle", Object::Integer(0)),
            ("Ascent", Object::Integer(emb.ascent as i64)),
            ("Descent", Object::Integer(emb.descent as i64)),
            ("CapHeight", Object::Integer(emb.cap_height as i64)),
            ("StemV", Object::Integer(80)),
            ("FontFile2", Object::Reference((file, 0))),
        ])),
        (file, Object::Stream(ff)),
        (tounicode, Object::Stream(tu)),
    ]
}

/// Ký PDF. Trả về (PDF đã ký, tên trường chữ ký).
pub fn sign_pdf(signer: &mut Signer, input: &[u8], opts: &PdfSignOptions) -> Result<(Vec<u8>, String), PdfError> {
    let doc = Document::load_mem(input).map_err(|e| PdfError::Parse(e.to_string()))?;
    if doc.is_encrypted() {
        return Err(PdfError::Encrypted);
    }
    let perr = |e: lopdf::Error| PdfError::Parse(e.to_string());
    let root_id = doc.trailer.get(b"Root").and_then(Object::as_reference).map_err(perr)?;
    let mut catalog = doc.get_object(root_id).and_then(Object::as_dict).map_err(perr)?.clone();

    let pages = doc.get_pages();
    let page_no = opts.visible.as_ref().map(|v| v.page).unwrap_or(1);
    let page_id = *pages.get(&page_no).ok_or(PdfError::NoPage(page_no))?;
    let mut page = doc.get_object(page_id).and_then(Object::as_dict).map_err(perr)?.clone();

    // AcroForm: có thể là tham chiếu, dict nội tuyến, hoặc chưa có.
    let (mut acro, acro_id): (Dictionary, Option<ObjectId>) = match catalog.get(b"AcroForm") {
        Ok(Object::Reference(id)) => (doc.get_object(*id).and_then(Object::as_dict).map_err(perr)?.clone(), Some(*id)),
        Ok(Object::Dictionary(d)) => (d.clone(), None),
        _ => (Dictionary::new(), None),
    };
    let mut fields: Vec<Object> = acro
        .get(b"Fields")
        .ok()
        .map(|f| resolve(&doc, f))
        .and_then(|f| f.as_array().ok())
        .cloned()
        .unwrap_or_default();
    let existing: Vec<Vec<u8>> = fields
        .iter()
        .filter_map(|f| resolve(&doc, f).as_dict().ok())
        .filter_map(|d| d.get(b"T").ok())
        .filter_map(|t| t.as_str().ok().map(|s| s.to_vec()))
        .collect();
    let field_name = (1..).map(|i| format!("Signature{i}")).find(|n| !existing.contains(&n.as_bytes().to_vec())).unwrap();

    let next = doc.max_id + 1;
    let (sig_id, widget_id, ap_id) = (next, next + 1, next + 2);
    // Font nhúng: Type0, CIDFont, FontDescriptor, FontFile2, ToUnicode
    let font_ids = [next + 3, next + 4, next + 5, next + 6, next + 7];
    let mut last_id = if opts.visible.is_some() { font_ids[4] } else { widget_id };

    // Annotation widget của trường chữ ký (ẩn: Rect 0 0 0 0)
    let rect = opts.visible.as_ref().map(|v| v.rect).unwrap_or([0.0; 4]);
    let mut widget = Dictionary::new();
    widget.set("Type", Object::Name(b"Annot".to_vec()));
    widget.set("Subtype", Object::Name(b"Widget".to_vec()));
    widget.set("FT", Object::Name(b"Sig".to_vec()));
    widget.set("T", text_string(&field_name));
    widget.set("V", Object::Reference((sig_id, 0)));
    widget.set("F", Object::Integer(132)); // Print + Locked
    widget.set("P", Object::Reference(page_id));
    widget.set("Rect", Object::Array(rect.iter().map(|x| Object::Real(*x)).collect()));

    let now = chrono::Local::now();
    let mut objects: BTreeMap<u32, (u16, Vec<u8>)> = BTreeMap::new();
    let mut put = |id: ObjectId, o: &Object| {
        let mut b = vec![];
        write_object(&mut b, o);
        objects.insert(id.0, (id.1, b));
    };

    if opts.visible.is_some() {
        let (w, h) = ((rect[2] - rect[0]).abs().max(1.0), (rect[3] - rect[1]).abs().max(1.0));
        let (content, emb) = appearance(signer, opts, w, h, &now)?;
        for (id, obj) in font_objects(&emb, font_ids) {
            put((id, 0), &obj);
        }
        let mut res = Dictionary::new();
        let mut fonts = Dictionary::new();
        fonts.set("F1", Object::Reference((font_ids[0], 0)));
        res.set("Font", Object::Dictionary(fonts));
        let mut sd = Dictionary::new();
        sd.set("Type", Object::Name(b"XObject".to_vec()));
        sd.set("Subtype", Object::Name(b"Form".to_vec()));
        sd.set("BBox", Object::Array(vec![0.into(), 0.into(), Object::Real(w), Object::Real(h)]));
        sd.set("Resources", Object::Dictionary(res));
        let mut ap_stream = lopdf::Stream::new(sd, content);
        let _ = ap_stream.compress();
        put((ap_id, 0), &Object::Stream(ap_stream));
        let mut ap = Dictionary::new();
        ap.set("N", Object::Reference((ap_id, 0)));
        widget.set("AP", Object::Dictionary(ap));
    }
    put((widget_id, 0), &Object::Dictionary(widget));

    // Gắn widget vào trang
    let mut annots: Vec<Object> = page
        .get(b"Annots")
        .ok()
        .map(|a| resolve(&doc, a))
        .and_then(|a| a.as_array().ok())
        .cloned()
        .unwrap_or_default();
    annots.push(Object::Reference((widget_id, 0)));
    page.set("Annots", Object::Array(annots));
    put(page_id, &Object::Dictionary(page));

    // Gắn trường vào AcroForm
    fields.push(Object::Reference((widget_id, 0)));
    acro.set("Fields", Object::Array(fields));
    acro.set("SigFlags", Object::Integer(3));
    match acro_id {
        Some(id) => put(id, &Object::Dictionary(acro)),
        None => {
            catalog.set("AcroForm", Object::Dictionary(acro));
            put(root_id, &Object::Dictionary(catalog));
        }
    }

    // ---- Ghi phần nối thêm ----
    let mut out = input.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let mut offsets: BTreeMap<u32, (usize, u16)> = BTreeMap::new();
    for (id, (gen, body)) in &objects {
        offsets.insert(*id, (out.len(), *gen));
        out.extend(format!("{id} {gen} obj\n").bytes());
        out.extend(body);
        out.extend(b"\nendobj\n");
    }

    // Đối tượng chữ ký với chỗ trống cho ByteRange và Contents
    let est = 8192
        + signer.cert.der().len()
        + signer.chain.iter().map(|c| c.der().len()).sum::<usize>()
        + if opts.tsa_url.as_deref().is_some_and(|u| !u.is_empty()) { 12288 } else { 0 };
    let br_placeholder = format!("[0 {0} {0} {0}]", "0".repeat(10));
    offsets.insert(sig_id, (out.len(), 0));
    let mut sig = format!("{sig_id} 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached");
    let mut extra = vec![];
    // Định dạng ngày PDF: D:YYYYMMDDHHmmSS+07'00'
    let m = format!("D:{}'", now.format("%Y%m%d%H%M%S%:z").to_string().replace(':', "'"));
    write_object(&mut extra, &Object::String(m.into_bytes(), StringFormat::Literal));
    sig += &format!(" /M {}", String::from_utf8_lossy(&extra));
    for (k, v) in [("Reason", &opts.reason), ("Location", &opts.location), ("ContactInfo", &opts.contact)] {
        if let Some(v) = v.as_deref().filter(|s| !s.is_empty()) {
            let mut b = vec![];
            write_object(&mut b, &text_string(v));
            sig += &format!(" /{k} {}", String::from_utf8_lossy(&b));
        }
    }
    let mut nb = vec![];
    write_object(&mut nb, &text_string(&signer.cert.subject_cn));
    sig += &format!(" /Name {} /ByteRange ", String::from_utf8_lossy(&nb));
    out.extend(sig.bytes());
    let br_pos = out.len();
    out.extend(br_placeholder.bytes());
    out.extend(b" /Contents ");
    let contents_start = out.len();
    out.push(b'<');
    out.extend(std::iter::repeat_n(b'0', est * 2));
    out.push(b'>');
    let contents_end = out.len();
    out.extend(b" >>\nendobj\n");

    // Bảng xref cho phần nối thêm: cùng kiểu với file gốc
    let prev = last_startxref(input).ok_or_else(|| PdfError::Parse("Không thấy startxref".into()))?;
    let is_stream_xref = !input.get(prev..).is_some_and(|b| b.starts_with(b"xref"));
    let mut trailer = Dictionary::new();
    trailer.set("Root", Object::Reference(root_id));
    for k in [&b"Info"[..], b"ID"] {
        if let Ok(v) = doc.trailer.get(k) {
            trailer.set(k.to_vec(), v.clone());
        }
    }
    trailer.set("Prev", Object::Integer(prev as i64));
    let old_size = doc.trailer.get(b"Size").and_then(Object::as_i64).unwrap_or(0) as u32;

    let xref_off = out.len();
    if is_stream_xref {
        last_id = last_id.max(sig_id) + 1;
        let xref_id = last_id;
        offsets.insert(xref_id, (xref_off, 0));
        let mut data = vec![];
        let mut index = vec![];
        for (id, (off, gen)) in &offsets {
            index.extend([Object::Integer(*id as i64), Object::Integer(1)]);
            data.push(1u8);
            data.extend((*off as u32).to_be_bytes());
            data.extend(gen.to_be_bytes());
        }
        trailer.set("Type", Object::Name(b"XRef".to_vec()));
        trailer.set("Size", Object::Integer(old_size.max(xref_id + 1) as i64));
        trailer.set("W", Object::Array(vec![1.into(), 4.into(), 2.into()]));
        trailer.set("Index", Object::Array(index));
        out.extend(format!("{xref_id} 0 obj\n").bytes());
        write_object(&mut out, &Object::Stream(lopdf::Stream::new(trailer, data)));
        out.extend(format!("\nendobj\nstartxref\n{xref_off}\n%%EOF\n").bytes());
    } else {
        let max_id = *offsets.keys().max().unwrap();
        out.extend(b"xref\n0 1\n0000000000 65535 f\r\n");
        for (id, (off, gen)) in &offsets {
            out.extend(format!("{id} 1\n{off:010} {gen:05} n\r\n").bytes());
        }
        trailer.set("Size", Object::Integer(old_size.max(max_id + 1) as i64));
        out.extend(b"trailer\n");
        write_dict(&mut out, &trailer);
        out.extend(format!("\nstartxref\n{xref_off}\n%%EOF\n").bytes());
    }

    // Điền ByteRange, băm, ký, nhét CMS vào Contents
    let total = out.len();
    let br = format!("[0 {contents_start} {contents_end} {}]", total - contents_end);
    let br = format!("{br:<width$}", width = br_placeholder.len());
    out[br_pos..br_pos + br.len()].copy_from_slice(br.as_bytes());

    let mut hasher_input = Vec::with_capacity(total);
    hasher_input.extend_from_slice(&out[..contents_start]);
    hasher_input.extend_from_slice(&out[contents_end..]);
    let md = opts.hash.digest(&hasher_input);
    let cms_opts = CmsOptions { hash: opts.hash, pss: opts.pss, attached: false, tsa_url: opts.tsa_url.clone(), pades: true };
    let cms = cms::build(signer, &md, None, &cms_opts)?;
    if cms.len() > est {
        return Err(PdfError::TooLarge(cms.len(), est));
    }
    let hx = hex::encode_upper(&cms);
    out[contents_start + 1..contents_start + 1 + hx.len()].copy_from_slice(hx.as_bytes());
    Ok((out, field_name))
}

/// Kích thước (rộng, cao) từng trang theo điểm PDF, đã tính /Rotate. Dùng để đặt khung chữ ký.
pub fn page_sizes(input: &[u8]) -> Result<Vec<(f32, f32)>, PdfError> {
    let doc = Document::load_mem(input).map_err(|e| PdfError::Parse(e.to_string()))?;
    let num = |o: &Object| o.as_float().ok().or_else(|| o.as_i64().ok().map(|i| i as f32)).unwrap_or(0.0);
    let mut out = vec![];
    for (_, id) in doc.get_pages() {
        // MediaBox/Rotate có thể kế thừa từ nút cha
        let (mut mb, mut rot, mut cur) = (None, 0i64, Some(id));
        while let Some(cid) = cur {
            let Ok(d) = doc.get_object(cid).and_then(Object::as_dict) else { break };
            if mb.is_none() {
                mb = d.get(b"MediaBox").ok().map(|m| resolve(&doc, m)).and_then(|m| m.as_array().ok()).cloned();
            }
            if rot == 0 {
                rot = d.get(b"Rotate").and_then(Object::as_i64).unwrap_or(0);
            }
            cur = d.get(b"Parent").and_then(Object::as_reference).ok();
        }
        let (w, h) = match mb.as_deref() {
            Some([a, b, c, d]) => ((num(c) - num(a)).abs(), (num(d) - num(b)).abs()),
            _ => (595.0, 842.0),
        };
        out.push(if rot.rem_euclid(180) == 90 { (h, w) } else { (w, h) });
    }
    Ok(out)
}
