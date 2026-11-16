//! Bộ mã hóa/giải mã DER tối giản, đủ cho CMS SignedData, DigestInfo và RFC 3161.

pub fn len_bytes(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let b: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|x| *x == 0).collect();
    let mut v = vec![0x80 | b.len() as u8];
    v.extend(b);
    v
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(len_bytes(content.len()));
    v.extend_from_slice(content);
    v
}

fn cat(items: &[&[u8]]) -> Vec<u8> {
    items.iter().flat_map(|i| i.iter().copied()).collect()
}

pub fn seq(items: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &cat(items))
}

/// SET OF: DER yêu cầu sắp xếp các phần tử theo mã hóa.
pub fn set_of(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = items.to_vec();
    v.sort();
    tlv(0x31, &v.concat())
}

/// [n] EXPLICIT hoặc IMPLICIT dạng constructed.
pub fn ctx(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xA0 | n, content)
}

pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub fn octet(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

pub fn boolean(b: bool) -> Vec<u8> {
    vec![0x01, 0x01, if b { 0xFF } else { 0x00 }]
}

pub fn int(n: u64) -> Vec<u8> {
    uint(&n.to_be_bytes())
}

/// INTEGER không âm từ byte big-endian (bỏ số 0 đầu, thêm 0x00 nếu bit cao bật).
pub fn uint(be: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = be.iter().copied().skip_while(|x| *x == 0).collect();
    if b.is_empty() || b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

/// INTEGER từ nội dung thô (đã đúng định dạng, ví dụ serial lấy từ chứng thư).
pub fn int_raw(content: &[u8]) -> Vec<u8> {
    tlv(0x02, content)
}

pub fn oid(dotted: &str) -> Vec<u8> {
    let parts: Vec<u64> = dotted.split('.').map(|p| p.parse().expect("OID hợp lệ")).collect();
    let mut body = vec![(parts[0] * 40 + parts[1]) as u8];
    for &p in &parts[2..] {
        let mut stack = vec![(p & 0x7F) as u8];
        let mut x = p >> 7;
        while x > 0 {
            stack.push(0x80 | (x & 0x7F) as u8);
            x >>= 7;
        }
        stack.reverse();
        body.extend(stack);
    }
    tlv(0x06, &body)
}

pub fn utc_time(t: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    tlv(0x17, t.format("%y%m%d%H%M%SZ").to_string().as_bytes())
}

// ------------------------------- Đọc -------------------------------

/// Một phần tử TLV: tag, nội dung, và toàn bộ byte của phần tử.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

pub fn read(buf: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *buf.first()?;
    let l0 = *buf.get(1)? as usize;
    let (len, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7F;
        if n == 0 || n > 8 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *buf.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((Tlv { tag, content: &buf[hdr..end], raw: &buf[..end] }, &buf[end..]))
}

/// Các phần tử con của một phần tử constructed.
pub fn children(content: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = vec![];
    let mut rest = content;
    while let Some((t, r)) = read(rest) {
        out.push(t);
        rest = r;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oid_encoding() {
        assert_eq!(oid("1.2.840.113549.1.7.2"), hex::decode("06092a864886f70d010702").unwrap());
        assert_eq!(oid("2.16.840.1.101.3.4.2.1"), hex::decode("0609608648016503040201").unwrap());
    }
    #[test]
    fn digest_info_prefix_matches_rfc8017() {
        let di = crate::signer::HashAlg::Sha256.digest_info(&[0u8; 32]);
        assert_eq!(&di[..19], &hex::decode("3031300d060960864801650304020105000420").unwrap()[..]);
    }
    #[test]
    fn long_length() {
        let v = tlv(0x04, &vec![1u8; 300]);
        assert_eq!(&v[..4], &[0x04, 0x82, 0x01, 0x2C]);
        let (t, rest) = read(&v).unwrap();
        assert_eq!(t.content.len(), 300);
        assert!(rest.is_empty());
    }
}
