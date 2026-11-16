//! CMS SignedData (RFC 5652) dạng CAdES-BES, dùng chung cho file .p7s và PDF (PAdES).

use crate::certinfo;
use crate::der::{self, ctx, oid, octet, seq, set_of};
use crate::signer::{HashAlg, SignError, Signer};
use crate::tsa;

const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const OID_SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";
const OID_TIMESTAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_MGF1: &str = "1.2.840.113549.1.1.8";

#[derive(Debug, Clone)]
pub struct CmsOptions {
    pub hash: HashAlg,
    pub pss: bool,
    /// Nhúng dữ liệu gốc vào CMS (mặc định: tách rời, .p7s đi kèm file gốc).
    pub attached: bool,
    pub tsa_url: Option<String>,
    /// PAdES: không đưa signingTime vào thuộc tính ký (thời gian nằm ở /M của PDF).
    pub pades: bool,
}

impl Default for CmsOptions {
    fn default() -> Self {
        Self { hash: HashAlg::Sha256, pss: false, attached: false, tsa_url: None, pades: false }
    }
}

fn alg_id(hash: HashAlg) -> Vec<u8> {
    seq(&[&oid(hash.oid())])
}

fn sig_alg(key_type: &str, hash: HashAlg, pss: bool) -> Vec<u8> {
    if key_type == "EC" {
        let o = match hash {
            HashAlg::Sha1 => "1.2.840.10045.4.1",
            HashAlg::Sha256 => "1.2.840.10045.4.3.2",
            HashAlg::Sha384 => "1.2.840.10045.4.3.3",
            HashAlg::Sha512 => "1.2.840.10045.4.3.4",
        };
        return seq(&[&oid(o)]);
    }
    if pss {
        let h = seq(&[&oid(hash.oid()), &der::null()]);
        let params = seq(&[&ctx(0, &h), &ctx(1, &seq(&[&oid(OID_MGF1), &h])), &ctx(2, &der::int(hash.len() as u64))]);
        return seq(&[&oid(OID_RSA_PSS), &params]);
    }
    seq(&[&oid(OID_RSA), &der::null()])
}

fn attr(o: &str, value: &[u8]) -> Vec<u8> {
    seq(&[&oid(o), &set_of(&[value.to_vec()])])
}

/// Ký `data` → ContentInfo(SignedData) DER.
pub fn sign_data(signer: &mut Signer, data: &[u8], opts: &CmsOptions) -> Result<Vec<u8>, SignError> {
    let md = opts.hash.digest(data);
    build(signer, &md, opts.attached.then_some(data), opts)
}

/// Dựng CMS từ băm của nội dung (PDF dùng cách này: băm ByteRange).
pub fn build(signer: &mut Signer, message_digest: &[u8], content: Option<&[u8]>, opts: &CmsOptions) -> Result<Vec<u8>, SignError> {
    let fail = |e: anyhow::Error| SignError::Failed(e.to_string());
    let cert_der = signer.cert.der();
    let parts = certinfo::parts(&cert_der).map_err(fail)?;

    // ESS signingCertificateV2: gắn chặt chữ ký với đúng chứng thư (bắt buộc với CAdES/PAdES).
    let cert_hash = HashAlg::Sha256.digest(&cert_der);
    let issuer_serial = seq(&[&seq(&[&ctx(4, &parts.issuer_der)]), &der::int_raw(&parts.serial)]);
    let ess = seq(&[&seq(&[&seq(&[&octet(&cert_hash), &issuer_serial])])]);

    let mut attrs = vec![
        attr(OID_CONTENT_TYPE, &oid(OID_DATA)),
        attr(OID_MESSAGE_DIGEST, &octet(message_digest)),
        attr(OID_SIGNING_CERT_V2, &ess),
    ];
    if !opts.pades {
        attrs.push(attr(OID_SIGNING_TIME, &der::utc_time(chrono::Utc::now())));
    }
    let signed_attrs = set_of(&attrs); // tag 0x31 khi ký
    let res = signer.sign(Some(&signed_attrs), None, opts.hash, opts.pss)?;

    let mut si_items: Vec<Vec<u8>> = vec![
        der::int(1),
        seq(&[&parts.issuer_der, &der::int_raw(&parts.serial)]),
        alg_id(opts.hash),
        {
            // Trong SignerInfo, signedAttrs là [0] IMPLICIT: cùng nội dung, đổi tag 0x31 → 0xA0.
            let mut implicit = signed_attrs.clone();
            implicit[0] = 0xA0;
            implicit
        },
        sig_alg(&signer.cert.key_type, opts.hash, opts.pss),
        octet(&res.signature),
    ];
    if let Some(url) = opts.tsa_url.as_deref().filter(|u| !u.is_empty()) {
        let token = tsa::timestamp(url, opts.hash, &res.signature).map_err(SignError::Failed)?;
        let unsigned = attr(OID_TIMESTAMP_TOKEN, &token);
        si_items.push(der::tlv(0xA1, &unsigned));
    }
    let si_refs: Vec<&[u8]> = si_items.iter().map(|v| v.as_slice()).collect();
    let signer_info = seq(&si_refs);

    let mut certs: Vec<u8> = cert_der.clone();
    for c in &signer.chain {
        certs.extend(c.der());
    }
    let encap = match content {
        Some(c) => seq(&[&oid(OID_DATA), &ctx(0, &octet(c))]),
        None => seq(&[&oid(OID_DATA)]),
    };
    let signed_data = seq(&[
        &der::int(1),
        &set_of(&[alg_id(opts.hash)]),
        &encap,
        &ctx(0, &certs),
        &set_of(&[signer_info]),
    ]);
    Ok(seq(&[&oid(OID_SIGNED_DATA), &ctx(0, &signed_data)]))
}
