//! Nhúng font TrueType có tiếng Việt vào PDF (Type0 / CIDFontType2, Identity-H).
//!
//! Font mặc định: Noto Sans (SIL Open Font License 1.1, xem assets/OFL.txt).
//! Chỉ nhúng các glyph thực sự dùng (subset), nên mỗi PDF chỉ nặng thêm vài KB,
//! kèm bảng ToUnicode để chữ trong khung chữ ký vẫn copy/tìm kiếm được.

use std::collections::BTreeMap;
use std::fmt::Write as _;

pub const DEFAULT_FONT: &[u8] = include_bytes!("../assets/NotoSans-Regular.ttf");

#[derive(Debug, thiserror::Error)]
pub enum FontError {
    #[error("Font không hợp lệ: {0}")]
    Parse(String),
    #[error("Không tạo được subset font: {0}")]
    Subset(String),
}

pub struct Font<'a> {
    data: &'a [u8],
    face: ttf_parser::Face<'a>,
    upem: f32,
}

/// Font đã subset, sẵn sàng ghi vào PDF.
pub struct EmbeddedFont {
    pub base_name: String,
    pub font_file: Vec<u8>,
    /// (gid mới, độ rộng theo đơn vị 1/1000 em)
    pub widths: Vec<(u16, u16)>,
    /// gid mới → ký tự
    pub to_unicode: BTreeMap<u16, char>,
    pub bbox: [i32; 4],
    pub ascent: i32,
    pub descent: i32,
    pub cap_height: i32,
    /// Mã hóa từng dòng thành chuỗi hex 2 byte/glyph cho toán tử Tj
    pub lines_hex: Vec<String>,
}

impl<'a> Font<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, FontError> {
        let face = ttf_parser::Face::parse(data, 0).map_err(|e| FontError::Parse(e.to_string()))?;
        let upem = face.units_per_em() as f32;
        Ok(Self { data, face, upem })
    }

    fn gid(&self, c: char) -> u16 {
        self.face
            .glyph_index(c)
            .or_else(|| self.face.glyph_index('?'))
            .map(|g| g.0)
            .unwrap_or(0)
    }

    fn advance(&self, gid: u16) -> f32 {
        self.face.glyph_hor_advance(ttf_parser::GlyphId(gid)).unwrap_or(0) as f32 * 1000.0 / self.upem
    }

    /// Bề rộng chuỗi theo điểm PDF ở cỡ chữ `size`.
    pub fn measure(&self, text: &str, size: f32) -> f32 {
        text.chars().map(|c| self.advance(self.gid(c))).sum::<f32>() * size / 1000.0
    }

    /// Ngắt dòng theo từ cho vừa `max_width` điểm.
    pub fn wrap(&self, text: &str, size: f32, max_width: f32) -> Vec<String> {
        let mut lines = vec![];
        let mut cur = String::new();
        for word in text.split_whitespace() {
            let candidate = if cur.is_empty() { word.to_string() } else { format!("{cur} {word}") };
            if self.measure(&candidate, size) <= max_width || cur.is_empty() {
                cur = candidate;
            } else {
                lines.push(std::mem::take(&mut cur));
                cur = word.to_string();
            }
        }
        if !cur.is_empty() {
            lines.push(cur);
        }
        lines
    }

    fn scale(&self, v: i16) -> i32 {
        (v as f32 * 1000.0 / self.upem).round() as i32
    }

    fn ps_name(&self) -> String {
        self.face
            .names()
            .into_iter()
            .find(|n| n.name_id == ttf_parser::name_id::POST_SCRIPT_NAME)
            .and_then(|n| n.to_string())
            .unwrap_or_else(|| "EmbeddedFont".into())
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect()
    }

    /// Subset font theo các dòng chữ và mã hóa từng dòng.
    pub fn embed(&self, lines: &[String]) -> Result<EmbeddedFont, FontError> {
        let mut old: Vec<u16> = lines.iter().flat_map(|l| l.chars().map(|c| self.gid(c))).collect();
        old.sort_unstable();
        old.dedup();
        let remap = subsetter::GlyphRemapper::new_from_glyphs_sorted(&old);
        let font_file = subsetter::subset(self.data, 0, &remap).map_err(|e| FontError::Subset(format!("{e:?}")))?;

        let mut to_unicode = BTreeMap::new();
        let mut widths = BTreeMap::new();
        let lines_hex = lines
            .iter()
            .map(|l| {
                let mut hx = String::new();
                for c in l.chars() {
                    let g = self.gid(c);
                    let ng = remap.get(g).unwrap_or(0);
                    to_unicode.entry(ng).or_insert(c);
                    widths.insert(ng, self.advance(g).round() as u16);
                    let _ = write!(hx, "{ng:04X}");
                }
                hx
            })
            .collect();

        let r = self.face.global_bounding_box();
        // Tiền tố subset 6 chữ cái (chuẩn PDF), suy ra từ nội dung để ổn định
        let h = crate::signer::HashAlg::Sha256.digest(lines.concat().as_bytes());
        let tag: String = h.iter().take(6).map(|b| (b'A' + b % 26) as char).collect();
        Ok(EmbeddedFont {
            base_name: format!("{tag}+{}", self.ps_name()),
            font_file,
            widths: widths.into_iter().collect(),
            to_unicode,
            bbox: [self.scale(r.x_min), self.scale(r.y_min), self.scale(r.x_max), self.scale(r.y_max)],
            ascent: self.scale(self.face.ascender()),
            descent: self.scale(self.face.descender()),
            cap_height: self.face.capital_height().map(|v| self.scale(v)).unwrap_or(700),
            lines_hex,
        })
    }
}

impl EmbeddedFont {
    /// CMap ToUnicode để trình đọc PDF chuyển glyph về lại Unicode (copy/tìm kiếm).
    pub fn to_unicode_cmap(&self) -> Vec<u8> {
        let mut s = String::from(
            "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
             /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
             /CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n\
             1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
        );
        let entries: Vec<_> = self.to_unicode.iter().collect();
        for chunk in entries.chunks(100) {
            let _ = writeln!(s, "{} beginbfchar", chunk.len());
            for (g, c) in chunk {
                let mut buf = [0u16; 2];
                let u: String = c.encode_utf16(&mut buf).iter().map(|x| format!("{x:04X}")).collect();
                let _ = writeln!(s, "<{g:04X}> <{u}>");
            }
            s.push_str("endbfchar\n");
        }
        s.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
        s.into_bytes()
    }
}
