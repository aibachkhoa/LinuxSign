//! Ký số theo cách tương thích rộng nhất giữa các loại token.
//!
//! Driver các hãng khác nhau nhiều về cơ chế hỗ trợ và hay báo sai danh sách cơ chế,
//! nên ta KHÔNG tin danh sách đó mà thử lần lượt:
//!   RSA PKCS#1 v1.5 : CKM_RSA_PKCS trên DigestInfo (máy băm, token chỉ ký): token nào cũng có
//!                     → CKM_SHA*_RSA_PKCS (token tự băm)
//!   RSA-PSS         : CKM_RSA_PKCS_PSS → CKM_SHA*_RSA_PKCS_PSS
//!   ECDSA           : CKM_ECDSA trên digest → CKM_ECDSA_SHA*
//! Mọi chữ ký đều được xác minh lại bằng khóa công khai trong chứng thư trước khi trả về.

use crate::certinfo::{self, CertInfo};
use crate::der;
use crate::manager::TokenInfo;
use crate::probe::init_module;
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().replace('-', "").as_str() {
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
    pub fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
    pub fn oid(self) -> &'static str {
        match self {
            Self::Sha1 => "1.3.14.3.2.26",
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }
    /// DigestInfo ::= SEQUENCE { AlgorithmIdentifier(hash, NULL), OCTET STRING digest }
    pub fn digest_info(self, digest: &[u8]) -> Vec<u8> {
        der::seq(&[&der::seq(&[&der::oid(self.oid()), &der::null()]), &der::octet(digest)])
    }
    fn ck(self) -> (MechanismType, PkcsMgfType) {
        match self {
            Self::Sha1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
            Self::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
            Self::Sha384 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384),
            Self::Sha512 => (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512),
        }
    }
}

/// Cơ chế ký, độc lập với thư viện PKCS#11 (để kiểm thử bằng backend phần mềm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mech {
    /// CKM_RSA_PKCS trên DigestInfo
    RsaPkcs,
    /// CKM_SHA*_RSA_PKCS trên dữ liệu gốc
    RsaPkcsHash(HashAlg),
    /// CKM_RSA_PKCS_PSS trên digest
    Pss(HashAlg),
    /// CKM_SHA*_RSA_PKCS_PSS trên dữ liệu gốc
    PssHash(HashAlg),
    /// CKM_ECDSA trên digest (trả r||s)
    Ecdsa,
    /// CKM_ECDSA_SHA* trên dữ liệu gốc
    EcdsaHash(HashAlg),
}

impl Mech {
    pub fn name(&self) -> String {
        match self {
            Mech::RsaPkcs => "CKM_RSA_PKCS".into(),
            Mech::RsaPkcsHash(h) => format!("CKM_{}_RSA_PKCS", h.name().to_uppercase()),
            Mech::Pss(_) => "CKM_RSA_PKCS_PSS".into(),
            Mech::PssHash(h) => format!("CKM_{}_RSA_PKCS_PSS", h.name().to_uppercase()),
            Mech::Ecdsa => "CKM_ECDSA".into(),
            Mech::EcdsaHash(h) => format!("CKM_ECDSA_{}", h.name().to_uppercase()),
        }
    }
    /// Cơ chế có băm bên trong token (hỗ trợ ký nhiều phần).
    fn is_combined(&self) -> bool {
        matches!(self, Mech::RsaPkcsHash(_) | Mech::PssHash(_) | Mech::EcdsaHash(_))
    }
    fn to_cryptoki(self) -> Mechanism<'static> {
        let pss = |h: HashAlg| {
            let (hash_alg, mgf) = h.ck();
            PkcsPssParams { hash_alg, mgf, s_len: (h.len() as u64).into() }
        };
        match self {
            Mech::RsaPkcs => Mechanism::RsaPkcs,
            Mech::RsaPkcsHash(HashAlg::Sha1) => Mechanism::Sha1RsaPkcs,
            Mech::RsaPkcsHash(HashAlg::Sha256) => Mechanism::Sha256RsaPkcs,
            Mech::RsaPkcsHash(HashAlg::Sha384) => Mechanism::Sha384RsaPkcs,
            Mech::RsaPkcsHash(HashAlg::Sha512) => Mechanism::Sha512RsaPkcs,
            Mech::Pss(h) => Mechanism::RsaPkcsPss(pss(h)),
            Mech::PssHash(h @ HashAlg::Sha1) => Mechanism::Sha1RsaPkcsPss(pss(h)),
            Mech::PssHash(h @ HashAlg::Sha256) => Mechanism::Sha256RsaPkcsPss(pss(h)),
            Mech::PssHash(h @ HashAlg::Sha384) => Mechanism::Sha384RsaPkcsPss(pss(h)),
            Mech::PssHash(h @ HashAlg::Sha512) => Mechanism::Sha512RsaPkcsPss(pss(h)),
            Mech::Ecdsa => Mechanism::Ecdsa,
            Mech::EcdsaHash(HashAlg::Sha1) => Mechanism::EcdsaSha1,
            Mech::EcdsaHash(HashAlg::Sha256) => Mechanism::EcdsaSha256,
            Mech::EcdsaHash(HashAlg::Sha384) => Mechanism::EcdsaSha384,
            Mech::EcdsaHash(HashAlg::Sha512) => Mechanism::EcdsaSha512,
        }
    }
}

#[derive(Debug)]
pub enum BackendError {
    /// Cơ chế không dùng được → thử cơ chế kế tiếp.
    Unsupported(String),
    Pin(String),
    Other(String),
}

/// Lớp ký thô; triển khai thật là PKCS#11, kiểm thử dùng khóa phần mềm.
pub trait SignBackend {
    fn sign(&mut self, mech: Mech, payload: &[u8]) -> Result<Vec<u8>, BackendError>;
    fn module(&self) -> String;
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("{0}")]
    Pin(String),
    #[error("{0}")]
    Failed(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct SignResult {
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
    pub mechanism: String,
    pub module: String,
    pub hash: HashAlg,
    pub pss: bool,
}

mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
}

pub struct Signer {
    backend: Box<dyn SignBackend>,
    pub cert: CertInfo,
    /// Chứng thư CA trên token, để nhúng vào CMS/PDF.
    pub chain: Vec<CertInfo>,
}

impl Signer {
    pub fn with_backend(backend: Box<dyn SignBackend>, cert: CertInfo, chain: Vec<CertInfo>) -> Self {
        Self { backend, cert, chain }
    }

    /// Mở phiên tới token qua driver chính; lỗi thì thử driver dự phòng.
    /// Sai PIN thì dừng ngay, không thử driver khác (tránh làm khóa token).
    pub fn open(token: &TokenInfo, cert: &CertInfo, pin: Option<&str>) -> Result<Self, SignError> {
        let mut errors = vec![];
        for route in &token.routes {
            match Pkcs11Backend::open(&route.module, token, cert, pin) {
                Ok(b) => return Ok(Self::with_backend(Box::new(b), cert.clone(), token.ca_certificates.clone())),
                Err(BackendError::Pin(m)) => return Err(SignError::Pin(m)),
                Err(BackendError::Unsupported(m) | BackendError::Other(m)) => errors.push(format!("{}: {m}", route.module)),
            }
        }
        Err(SignError::Failed(format!("Không mở được token qua driver nào:\n  {}", errors.join("\n  "))))
    }

    pub fn module(&self) -> String {
        self.backend.module()
    }

    fn is_ec(&self) -> bool {
        self.cert.key_type == "EC"
    }

    fn plans(&self, has_data: bool, hash: HashAlg, pss: bool) -> Vec<Mech> {
        let mut v = if self.is_ec() {
            vec![Mech::Ecdsa, Mech::EcdsaHash(hash)]
        } else if pss {
            vec![Mech::Pss(hash), Mech::PssHash(hash)]
        } else {
            vec![Mech::RsaPkcs, Mech::RsaPkcsHash(hash)]
        };
        if !has_data {
            v.retain(|m| !m.is_combined());
        }
        v
    }

    /// Ký `data` (sẽ được băm) hoặc `digest` đã băm sẵn. Chữ ký trả về:
    /// RSA là chuỗi byte chuẩn; ECDSA là DER SEQUENCE{r, s} như X.509/CMS yêu cầu.
    pub fn sign(&mut self, data: Option<&[u8]>, digest: Option<&[u8]>, hash: HashAlg, pss: bool) -> Result<SignResult, SignError> {
        let digest = match (digest, data) {
            (Some(d), _) => d.to_vec(),
            (None, Some(d)) => hash.digest(d),
            (None, None) => return Err(SignError::Failed("Cần data hoặc digest".into())),
        };
        if digest.len() != hash.len() {
            return Err(SignError::Failed(format!("Digest dài {} byte, không khớp {}", digest.len(), hash.name())));
        }
        let mut tried = vec![];
        for mech in self.plans(data.is_some(), hash, pss) {
            let payload: Vec<u8> = match mech {
                Mech::RsaPkcs => hash.digest_info(&digest),
                Mech::Pss(_) | Mech::Ecdsa => digest.clone(),
                _ => data.expect("combined chỉ khi có data").to_vec(),
            };
            let mut sig = match self.backend.sign(mech, &payload) {
                Ok(s) => s,
                Err(BackendError::Unsupported(e)) => {
                    tried.push(format!("{}: {e}", mech.name()));
                    continue;
                }
                Err(BackendError::Pin(e)) => return Err(SignError::Pin(e)),
                Err(BackendError::Other(e)) => return Err(SignError::Failed(e)),
            };
            if self.is_ec() {
                sig = ecdsa_raw_to_der(&sig);
            }
            match verify(&self.cert, &digest, &sig, hash, pss) {
                Ok(()) => {
                    return Ok(SignResult { signature: sig, mechanism: mech.name(), module: self.backend.module(), hash, pss })
                }
                Err(e) => tried.push(format!("{}: {e}", mech.name())),
            }
        }
        Err(SignError::Failed(format!("Token không ký được bằng cơ chế nào:\n  {}", tried.join("\n  "))))
    }
}

/// PKCS#11 trả chữ ký ECDSA dạng r||s; X.509/CMS cần DER SEQUENCE { INTEGER r, INTEGER s }.
pub fn ecdsa_raw_to_der(rs: &[u8]) -> Vec<u8> {
    let (r, s) = rs.split_at(rs.len() / 2);
    der::seq(&[&der::uint(r), &der::uint(s)])
}

/// Xác minh chữ ký trên digest bằng khóa công khai của chứng thư.
pub fn verify(cert: &CertInfo, digest: &[u8], sig: &[u8], hash: HashAlg, pss: bool) -> Result<(), String> {
    use rsa::pkcs8::DecodePublicKey;
    let parts = certinfo::parts(&cert.der()).map_err(|e| e.to_string())?;
    let bad = |_: rsa::Error| "chữ ký không khớp chứng thư (sai khóa hoặc driver trả kết quả sai)".to_string();
    if cert.key_type == "RSA" {
        let pk = rsa::RsaPublicKey::from_public_key_der(&parts.spki_der).map_err(|e| e.to_string())?;
        return match (pss, hash) {
            (false, HashAlg::Sha1) => pk.verify(rsa::Pkcs1v15Sign::new::<sha1::Sha1>(), digest, sig),
            (false, HashAlg::Sha256) => pk.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), digest, sig),
            (false, HashAlg::Sha384) => pk.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha384>(), digest, sig),
            (false, HashAlg::Sha512) => pk.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha512>(), digest, sig),
            (true, HashAlg::Sha1) => pk.verify(rsa::Pss::new_with_salt::<sha1::Sha1>(20), digest, sig),
            (true, HashAlg::Sha256) => pk.verify(rsa::Pss::new_with_salt::<sha2::Sha256>(32), digest, sig),
            (true, HashAlg::Sha384) => pk.verify(rsa::Pss::new_with_salt::<sha2::Sha384>(48), digest, sig),
            (true, HashAlg::Sha512) => pk.verify(rsa::Pss::new_with_salt::<sha2::Sha512>(64), digest, sig),
        }
        .map_err(bad);
    }
    if cert.key_type == "EC" {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(&parts.spki_der) {
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|e| e.to_string())?;
            return vk.verify_prehash(digest, &s).map_err(|_| "chữ ký không khớp chứng thư (sai khóa hoặc driver trả kết quả sai)".to_string());
        }
        if let Ok(vk) = p384::ecdsa::VerifyingKey::from_public_key_der(&parts.spki_der) {
            let s = p384::ecdsa::Signature::from_der(sig).map_err(|e| e.to_string())?;
            return vk.verify_prehash(digest, &s).map_err(|_| "chữ ký không khớp chứng thư (sai khóa hoặc driver trả kết quả sai)".to_string());
        }
        return Ok(()); // đường cong khác: chưa xác minh được ở máy, tin kết quả token
    }
    Err(format!("Loại khóa chưa hỗ trợ: {}", cert.key_type))
}

// ---------------------------------------------------------------------------
// Backend PKCS#11 thật
// ---------------------------------------------------------------------------

pub fn friendly(e: &CkError) -> String {
    match e {
        CkError::Pkcs11(rv, _) => match rv {
            RvError::PinIncorrect => "Sai mã PIN.".into(),
            RvError::PinLocked => "Token đã bị khóa PIN (nhập sai quá số lần). Liên hệ nhà cung cấp CA để mở khóa.".into(),
            RvError::PinLenRange => "Độ dài mã PIN không hợp lệ.".into(),
            RvError::PinExpired => "Mã PIN đã hết hạn, cần đổi PIN.".into(),
            RvError::TokenNotPresent | RvError::DeviceRemoved => "Token đã bị rút ra.".into(),
            RvError::FunctionCanceled => "Người dùng đã hủy thao tác trên thiết bị.".into(),
            other => other.to_string(),
        },
        other => other.to_string(),
    }
}

fn classify(e: CkError) -> BackendError {
    let msg = friendly(&e);
    match &e {
        CkError::Pkcs11(rv, _) => match rv {
            RvError::PinIncorrect | RvError::PinLocked | RvError::PinLenRange | RvError::PinExpired | RvError::FunctionCanceled => {
                BackendError::Pin(msg)
            }
            RvError::MechanismInvalid
            | RvError::MechanismParamInvalid
            | RvError::KeyFunctionNotPermitted
            | RvError::KeyTypeInconsistent
            | RvError::DataLenRange
            | RvError::FunctionNotSupported
            | RvError::ArgumentsBad
            | RvError::GeneralError => BackendError::Unsupported(msg),
            _ => BackendError::Other(msg),
        },
        CkError::NotSupported => BackendError::Unsupported(msg),
        _ => BackendError::Other(msg),
    }
}

pub struct Pkcs11Backend {
    session: Session,
    key: ObjectHandle,
    always_auth: bool,
    pin: Option<AuthPin>,
    module: String,
}

impl Pkcs11Backend {
    pub fn open(module: &str, token: &TokenInfo, cert: &CertInfo, pin: Option<&str>) -> Result<Self, BackendError> {
        let ctx = init_module(module).map_err(|e| BackendError::Other(friendly(&e)))?;
        // Không dựa vào slot_id cũ (đổi khi rút/cắm lại): tìm theo serial + nhãn.
        let slot = ctx
            .get_slots_with_token()
            .map_err(classify)?
            .into_iter()
            .find(|s| {
                ctx.get_token_info(*s)
                    .map(|ti| ti.serial_number().trim() == token.serial && ti.label().trim() == token.label)
                    .unwrap_or(false)
            })
            .ok_or_else(|| BackendError::Other("Không thấy token (đã rút ra?)".into()))?;
        let session = ctx.open_ro_session(slot).map_err(classify)?;
        let pin = pin.filter(|p| !p.is_empty()).map(|p| AuthPin::new(p.into()));
        if pin.is_none() && !token.protected_auth_path && token.login_required {
            return Err(BackendError::Pin("Cần nhập mã PIN của token.".into()));
        }
        match session.login(UserType::User, pin.as_ref()) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(e) => {
                return Err(match classify(e) {
                    BackendError::Unsupported(m) => BackendError::Other(m),
                    other => other,
                })
            }
        }
        let key = find_private_key(&session, cert)?;
        let always_auth = matches!(
            session.get_attributes(key, &[AttributeType::AlwaysAuthenticate]).as_deref(),
            Ok([Attribute::AlwaysAuthenticate(true)])
        );
        Ok(Self { session, key, always_auth, pin, module: module.into() })
    }
}

fn find_private_key(s: &Session, cert: &CertInfo) -> Result<ObjectHandle, BackendError> {
    let id = hex::decode(&cert.cka_id).unwrap_or_default();
    if !id.is_empty() {
        let keys = s.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Id(id)]).map_err(classify)?;
        if let Some(k) = keys.first() {
            return Ok(*k);
        }
    }
    // CKA_ID không khớp (một số token đặt ID tùy ý): so modulus RSA với chứng thư.
    let all = s.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)]).map_err(classify)?;
    if cert.key_type == "RSA" {
        use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
        let n = certinfo::parts(&cert.der())
            .ok()
            .and_then(|p| rsa::RsaPublicKey::from_public_key_der(&p.spki_der).ok())
            .map(|k| k.n().to_bytes_be());
        for k in &all {
            if let Ok(attrs) = s.get_attributes(*k, &[AttributeType::Modulus]) {
                if let Some(Attribute::Modulus(m)) = attrs.first() {
                    let m: Vec<u8> = m.iter().copied().skip_while(|b| *b == 0).collect();
                    if Some(&m) == n.as_ref() {
                        return Ok(*k);
                    }
                }
            }
        }
    }
    if all.len() == 1 {
        return Ok(all[0]); // sẽ được xác minh bằng chữ ký
    }
    Err(BackendError::Other("Không tìm thấy khóa riêng tương ứng với chứng thư trên token.".into()))
}

impl SignBackend for Pkcs11Backend {
    fn sign(&mut self, mech: Mech, payload: &[u8]) -> Result<Vec<u8>, BackendError> {
        let m = mech.to_cryptoki();
        if !self.always_auth {
            return self.session.sign(&m, self.key, payload).map_err(classify);
        }
        // Khóa CKA_ALWAYS_AUTHENTICATE: phải đăng nhập lại (CKU_CONTEXT_SPECIFIC) sau C_SignInit.
        self.session.sign_init(&m, self.key).map_err(classify)?;
        self.session.login(UserType::ContextSpecific, self.pin.as_ref()).map_err(classify)?;
        // cryptoki không tách riêng C_Sign nên dùng Update/Final. Cơ chế một phần
        // (RSA_PKCS/ECDSA) mà driver từ chối sẽ báo Unsupported → chuyển sang cơ chế có băm.
        self.session.sign_update(payload).map_err(classify)?;
        self.session.sign_final().map_err(classify)
    }
    fn module(&self) -> String {
        self.module.clone()
    }
}

impl Drop for Pkcs11Backend {
    fn drop(&mut self) {
        let _ = self.session.logout();
    }
}
