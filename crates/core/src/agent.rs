//! Signing agent HTTP chạy ở localhost cho ứng dụng web.
//!
//! Cùng mô hình với plugin ký số của các CA trên Windows: trang web gọi
//! http://127.0.0.1:<port>, agent ký bằng token rồi trả kết quả.
//!
//! API (JSON):
//!   GET  /health
//!   GET  /certificates[?refresh]
//!   POST /sign      {cert_id, pin, data_b64 | digest_b64, hash?, pss?, format?: "raw"|"cms", attached?, tsa_url?}
//!   POST /sign/pdf  {cert_id, pin, pdf_b64, reason?, location?, page?, rect?: [x1,y1,x2,y2], tsa_url?}
//!   POST /sign/xml  {cert_id, pin, xml_b64, profile?: "einvoice"|"enveloped"|"xades", reference_id?, parent_path?, signature_id?}
//!
//! Bảo mật: chỉ nghe 127.0.0.1; chỉ nhận request từ Origin trong danh sách cho phép
//! (request không có Origin = ứng dụng cục bộ, được phép); PIN không được lưu.

use crate::cms::{self, CmsOptions};
use crate::config::Config;
use crate::manager::{find_certificate, scan, Report};
use crate::pdf::{self, PdfSignOptions, VisibleSignature};
use crate::xml::{self, XmlProfile, XmlSignOptions};
use crate::signer::{HashAlg, SignError, Signer};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Request, Response, Server};

const CACHE_TTL: Duration = Duration::from_secs(10);
const MAX_BODY: usize = 200 * 1024 * 1024;

pub struct AgentHandle {
    server: Arc<Server>,
    thread: Option<std::thread::JoinHandle<()>>,
    pub port: u16,
}

impl AgentHandle {
    pub fn stop(mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct State {
    cfg: Config,
    cache: Mutex<Option<(Report, Instant)>>,
}

impl State {
    fn report(&self, refresh: bool) -> Report {
        let mut c = self.cache.lock().unwrap();
        if refresh || c.as_ref().is_none_or(|(_, t)| t.elapsed() > CACHE_TTL) {
            *c = Some((scan(&self.cfg, false), Instant::now()));
        }
        c.as_ref().unwrap().0.clone()
    }
}

pub fn start(cfg: Config, port: u16) -> Result<AgentHandle, String> {
    let server = Arc::new(Server::http(("127.0.0.1", port)).map_err(|e| format!("Không mở được cổng {port}: {e}"))?);
    let state = Arc::new(State { cfg, cache: Mutex::new(None) });
    let srv = server.clone();
    let thread = std::thread::spawn(move || {
        for req in srv.incoming_requests() {
            handle(&state, req);
        }
    });
    Ok(AgentHandle { server, thread: Some(thread), port })
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("header hợp lệ")
}

fn origin_of(req: &Request) -> Option<String> {
    req.headers().iter().find(|h| h.field.equiv("Origin")).map(|h| h.value.as_str().to_string())
}

fn handle(state: &State, mut req: Request) {
    let origin = origin_of(&req);
    let allowed = origin.as_ref().is_none_or(|o| state.cfg.agent_allowed_origins.iter().any(|a| a == o || a == "*"));
    let respond = |req: Request, code: u16, body: Value| {
        let mut r = Response::from_data(body.to_string().into_bytes())
            .with_status_code(code)
            .with_header(header("Content-Type", "application/json; charset=utf-8"));
        if let (Some(o), true) = (&origin, allowed) {
            r = r.with_header(header("Access-Control-Allow-Origin", o)).with_header(header("Vary", "Origin"));
        }
        let _ = req.respond(r);
    };
    if !allowed {
        return respond(req, 403, json!({"error": "Origin không được phép", "code": "ORIGIN"}));
    }
    let url = req.url().to_string();
    match (req.method().clone(), url.split('?').next().unwrap_or("")) {
        (Method::Options, _) => {
            let r = Response::empty(204)
                .with_header(header("Access-Control-Allow-Origin", origin.as_deref().unwrap_or("")))
                .with_header(header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
                .with_header(header("Access-Control-Allow-Headers", "Content-Type"))
                .with_header(header("Access-Control-Allow-Private-Network", "true"));
            let _ = req.respond(r);
        }
        (Method::Get, "/health") => respond(req, 200, json!({"ok": true, "version": crate::VERSION})),
        (Method::Get, "/certificates") => {
            let r = state.report(url.contains("refresh"));
            respond(req, 200, json!({ "tokens": r.tokens }))
        }
        (Method::Post, path @ ("/sign" | "/sign/pdf" | "/sign/xml")) => {
            let path = path.to_string();
            let mut body = vec![];
            let len = req.body_length().unwrap_or(0);
            if len == 0 || len > MAX_BODY || req.as_reader().read_to_end(&mut body).is_err() {
                return respond(req, 400, json!({"error": "Body rỗng hoặc quá lớn"}));
            }
            let Ok(v) = serde_json::from_slice::<Value>(&body) else {
                return respond(req, 400, json!({"error": "JSON không hợp lệ"}));
            };
            let (code, out) = match do_sign(state, &path, &v) {
                Ok(out) => (200, out),
                Err(AgentError::Pin(m)) => (401, json!({"error": m, "code": "PIN"})),
                Err(AgentError::NotFound(m)) => (404, json!({"error": m, "code": "CERT_NOT_FOUND"})),
                Err(AgentError::Bad(m)) => (400, json!({"error": m, "code": "BAD_REQUEST"})),
                Err(AgentError::Failed(m)) => (500, json!({"error": m, "code": "SIGN_FAILED"})),
            };
            respond(req, code, out)
        }
        _ => respond(req, 404, json!({"error": "Không có endpoint này"})),
    }
}


enum AgentError {
    Pin(String),
    NotFound(String),
    Bad(String),
    Failed(String),
}

impl From<SignError> for AgentError {
    fn from(e: SignError) -> Self {
        match e {
            SignError::Pin(m) => AgentError::Pin(m),
            SignError::Failed(m) => AgentError::Failed(m),
        }
    }
}

fn b64_field(v: &Value, k: &str) -> Result<Option<Vec<u8>>, AgentError> {
    match v.get(k).and_then(Value::as_str) {
        None => Ok(None),
        Some(s) => B64.decode(s).map(Some).map_err(|_| AgentError::Bad(format!("{k} không phải base64"))),
    }
}

fn do_sign(state: &State, path: &str, v: &Value) -> Result<Value, AgentError> {
    let report = state.report(false);
    let (token, cert) = find_certificate(&report, v.get("cert_id").and_then(Value::as_str)).map_err(|e| AgentError::NotFound(e.to_string()))?;
    let hash = HashAlg::parse(v.get("hash").and_then(Value::as_str).unwrap_or("sha256")).ok_or(AgentError::Bad("hash không hỗ trợ".into()))?;
    let pss = v.get("pss").and_then(Value::as_bool).unwrap_or(false);
    let tsa = v.get("tsa_url").and_then(Value::as_str).map(str::to_string).or(state.cfg.tsa_url.clone());
    let mut signer = Signer::open(token, cert, v.get("pin").and_then(Value::as_str))?;

    if path == "/sign/xml" {
        let input = b64_field(v, "xml_b64")?.ok_or(AgentError::Bad("thiếu xml_b64".into()))?;
        let profile = XmlProfile::parse(v.get("profile").and_then(Value::as_str).unwrap_or("enveloped"))
            .ok_or(AgentError::Bad("profile phải là einvoice | enveloped | xades".into()))?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).filter(|x| !x.is_empty()).map(str::to_string);
        let opts = XmlSignOptions { profile, hash, reference_id: s("reference_id"), parent_path: s("parent_path"), signature_id: s("signature_id") };
        let out = xml::sign_xml(&mut signer, &input, &opts).map_err(|e| match e {
            xml::XmlError::Sign(s) => s.into(),
            other => AgentError::Bad(other.to_string()),
        })?;
        return Ok(json!({"xml_b64": B64.encode(out)}));
    }
    if path == "/sign/pdf" {
        let input = b64_field(v, "pdf_b64")?.ok_or(AgentError::Bad("thiếu pdf_b64".into()))?;
        let visible = v.get("rect").and_then(Value::as_array).filter(|a| a.len() == 4).map(|a| VisibleSignature {
            page: v.get("page").and_then(Value::as_u64).unwrap_or(1) as u32,
            rect: [0, 1, 2, 3].map(|i| a[i].as_f64().unwrap_or(0.0) as f32),
        });
        let opts = PdfSignOptions {
            reason: v.get("reason").and_then(Value::as_str).map(str::to_string),
            location: v.get("location").and_then(Value::as_str).map(str::to_string),
            contact: None,
            hash,
            pss,
            tsa_url: tsa,
            visible,
            font: state.cfg.load_font(),
        };
        let (out, field) = pdf::sign_pdf(&mut signer, &input, &opts).map_err(|e| match e {
            pdf::PdfError::Sign(s) => s.into(),
            other => AgentError::Failed(other.to_string()),
        })?;
        return Ok(json!({"pdf_b64": B64.encode(out), "field": field}));
    }

    let data = b64_field(v, "data_b64")?;
    if v.get("format").and_then(Value::as_str) == Some("cms") {
        let data = data.ok_or(AgentError::Bad("format=cms cần data_b64".into()))?;
        let opts = CmsOptions { hash, pss, attached: v.get("attached").and_then(Value::as_bool).unwrap_or(false), tsa_url: tsa, pades: false };
        let der = cms::sign_data(&mut signer, &data, &opts)?;
        return Ok(json!({"cms_b64": B64.encode(der), "format": "cms"}));
    }
    let digest = b64_field(v, "digest_b64")?;
    let r = signer.sign(data.as_deref(), digest.as_deref(), hash, pss)?;
    Ok(json!({
        "signature_b64": B64.encode(&r.signature),
        "mechanism": r.mechanism,
        "hash": r.hash,
        "certificate_b64": cert.der_b64,
    }))
}
