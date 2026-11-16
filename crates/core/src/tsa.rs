//! Dấu thời gian RFC 3161: gửi băm của chữ ký tới máy chủ TSA, nhận TimeStampToken.

use crate::der;
use crate::signer::HashAlg;
use std::time::Duration;

pub fn timestamp(url: &str, hash: HashAlg, data: &[u8]) -> Result<Vec<u8>, String> {
    let digest = hash.digest(data);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64 ^ ((std::process::id() as u64) << 32))
        .unwrap_or(1);
    // TimeStampReq ::= SEQUENCE { version 1, messageImprint, nonce, certReq TRUE }
    let req = der::seq(&[
        &der::int(1),
        &der::seq(&[&der::seq(&[&der::oid(hash.oid())]), &der::octet(&digest)]),
        &der::int(nonce >> 1),
        &der::boolean(true),
    ]);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .into();
    let mut resp = agent
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .send(&req[..])
        .map_err(|e| format!("Không kết nối được máy chủ dấu thời gian {url}: {e}"))?;
    let body = resp.body_mut().read_to_vec().map_err(|e| e.to_string())?;
    parse_response(&body)
}

/// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
pub fn parse_response(body: &[u8]) -> Result<Vec<u8>, String> {
    let (top, _) = der::read(body).ok_or("Phản hồi TSA không hợp lệ")?;
    let items = der::children(top.content);
    let status = items.first().map(|s| der::children(s.content)).ok_or("Thiếu trạng thái TSA")?;
    let code = status.first().and_then(|i| i.content.last().copied()).unwrap_or(255);
    if code > 1 {
        return Err(format!("Máy chủ TSA từ chối (mã {code})"));
    }
    items.get(1).map(|t| t.raw.to_vec()).ok_or_else(|| "Phản hồi TSA không có token".into())
}
