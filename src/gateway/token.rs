//! Verification of bearer token signatures against configured issuers.
//!
//! A token is a JWS compact serialization (a signed JWT). Each configured issuer has its own keys,
//! checked when the configuration loads; one unusable key refuses the whole configuration. The
//! signing algorithm is fixed by the selected key, never taken from the token alone.
//!
//! Signatures are verified with `jsonwebtoken`. The key checks here run before it sees a key,
//! because it accepts shared-secret keys and does not check curves. Its own claim checks are off:
//! it reads the clock itself and ignores `iat`, so the claims are checked here.
//!
//! A verified token must name the issuer's audience, be current within 30 seconds of leeway, live
//! no longer than the issuer allows, and carry the issuer's required claim values. A token that
//! names a key in `cnf` is refused, because a bearer token cannot prove it holds that key. A token
//! ID (`jti`) is recorded only after every other check has passed, and a recorded ID is refused
//! until its token expires.
//!
//! Rejections carry fixed reasons only: nothing from the token is ever placed in an error or log.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, errors::ErrorKind};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::{Mutex, RwLock},
};

/// Clock skew tolerated on `exp`, `iat` and `nbf`.
const LEEWAY_SECONDS: u64 = 30;
const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_TOKEN_ID_BYTES: usize = 256;
const MAX_RECORDED_TOKEN_IDS: usize = 100_000;
const MIN_RSA_MODULUS_BYTES: usize = 256;
/// Members only a private or shared-secret key has. A key set that carries one has published a
/// secret.
const SECRET_KEY_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// One issuer whose tokens may be accepted.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssuerConfig {
    /// The exact `iss` value.
    pub issuer: String,
    /// The audience a token must name in `aud`.
    pub audience: String,
    /// Verification keys, as a JSON Web Key Set.
    pub keys: JwkSet,
    /// The longest lifetime accepted, measured as `exp` minus `iat`.
    pub max_lifetime_seconds: u64,
    /// Claims that must be present, as strings with exactly these values.
    #[serde(default)]
    pub required_claims: BTreeMap<String, String>,
    /// Whether a token must carry `jti`. A token that carries one is accepted only once.
    #[serde(default)]
    pub require_jti: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// A JSON Web Key. Only the members needed to verify signatures are used; any other member is kept
/// so that a secret-key member can be refused.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default, rename = "use")]
    pub usage: Option<String>,
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// A token whose signature a configured issuer's key verified.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Signed {
    pub issuer: String,
    pub claims: Map<String, Value>,
}

/// What a verified token established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Verified {
    pub issuer: String,
    pub subject: Option<String>,
    pub token_id: Option<String>,
    pub expires_at: u64,
}

/// Why a token was refused. The reasons are fixed strings and carry no token content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    Malformed,
    UnknownIssuer,
    UnknownKey,
    BadSignature,
    WrongAudience,
    Expired,
    NotYetValid,
    LifetimeTooLong,
    MissingClaim,
    ClaimMismatch,
    Reused,
    TooManyRecordedTokens,
    ProofRequired,
}

impl Rejection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnknownIssuer => "unknown_issuer",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::WrongAudience => "wrong_audience",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::LifetimeTooLong => "lifetime_too_long",
            Self::MissingClaim => "missing_claim",
            Self::ClaimMismatch => "claim_mismatch",
            Self::Reused => "reused",
            Self::TooManyRecordedTokens => "too_many_recorded_tokens",
            Self::ProofRequired => "proof_required",
        }
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

struct VerifyingKey {
    kid: Option<String>,
    algorithm: Algorithm,
    key: DecodingKey,
}

impl VerifyingKey {
    fn from_jwk(jwk: &Jwk) -> Result<Self, String> {
        if jwk.usage.as_deref().is_some_and(|usage| usage != "sig") {
            return Err("a key's \"use\" must be \"sig\" when present".into());
        }
        if SECRET_KEY_MEMBERS
            .iter()
            .any(|member| jwk.other.contains_key(*member))
        {
            return Err("a key must not carry secret-key members".into());
        }
        let (algorithm, key) = match (jwk.kty.as_str(), jwk.crv.as_deref()) {
            ("OKP", Some("Ed25519")) => {
                let (x, decoded) = key_member(&jwk.x, "x")?;
                if decoded.len() != 32 {
                    return Err("an Ed25519 key must be 32 bytes".into());
                }
                (Algorithm::EdDSA, DecodingKey::from_ed_components(x))
            }
            ("EC", Some("P-256")) => {
                let ((x, x_decoded), (y, y_decoded)) =
                    (key_member(&jwk.x, "x")?, key_member(&jwk.y, "y")?);
                if x_decoded.len() != 32 || y_decoded.len() != 32 {
                    return Err("a P-256 key's coordinates must be 32 bytes each".into());
                }
                (Algorithm::ES256, DecodingKey::from_ec_components(x, y))
            }
            ("RSA", _) => {
                let ((n, n_decoded), (e, e_decoded)) =
                    (key_member(&jwk.n, "n")?, key_member(&jwk.e, "e")?);
                if n_decoded.len() < MIN_RSA_MODULUS_BYTES {
                    return Err("an RSA key must be at least 2048 bits".into());
                }
                if e_decoded.is_empty() {
                    return Err("an RSA key needs an exponent".into());
                }
                (Algorithm::RS256, DecodingKey::from_rsa_components(n, e))
            }
            _ => return Err("supported keys are OKP Ed25519, EC P-256 and RSA".into()),
        };
        if jwk
            .alg
            .as_deref()
            .is_some_and(|alg| alg != algorithm_name(algorithm))
        {
            return Err("a key's \"alg\" must match its type".into());
        }
        Ok(Self {
            kid: jwk.kid.clone(),
            algorithm,
            key: key.map_err(|_| "a key member is not base64url".to_owned())?,
        })
    }
}

/// A key member as given and as decoded, for the size checks before the key is built.
fn key_member<'a>(value: &'a Option<String>, name: &str) -> Result<(&'a str, Vec<u8>), String> {
    let encoded = value
        .as_deref()
        .ok_or_else(|| format!("key member \"{name}\" is missing"))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| format!("key member \"{name}\" is not base64url"))?;
    Ok((encoded, decoded))
}

fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::EdDSA => "EdDSA",
        Algorithm::ES256 => "ES256",
        _ => "RS256",
    }
}

struct Issuer {
    config: IssuerConfig,
    keys: Vec<VerifyingKey>,
}

/// Verifies tokens against the configured issuers, and records the token IDs it has accepted.
pub(crate) struct Verifier {
    issuers: RwLock<HashMap<String, Issuer>>,
    recorded: Mutex<HashMap<(String, String), u64>>,
}

impl Verifier {
    pub(crate) fn new(configs: &[IssuerConfig]) -> Result<Self, String> {
        Ok(Self {
            issuers: RwLock::new(Self::issuers(configs)?),
            recorded: Mutex::new(HashMap::new()),
        })
    }

    fn issuers(configs: &[IssuerConfig]) -> Result<HashMap<String, Issuer>, String> {
        let mut issuers = HashMap::new();
        for config in configs {
            if config.issuer.is_empty() || config.audience.is_empty() {
                return Err("an issuer needs a non-empty issuer and audience".into());
            }
            if config.max_lifetime_seconds == 0 {
                return Err("an issuer's max_lifetime_seconds must be positive".into());
            }
            if config.keys.keys.is_empty() {
                return Err(format!("issuer {} has no keys", config.issuer));
            }
            let keys = config
                .keys
                .keys
                .iter()
                .map(VerifyingKey::from_jwk)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("issuer {}: {error}", config.issuer))?;
            let mut kids = HashSet::new();
            if keys
                .iter()
                .filter_map(|key| key.kid.as_deref())
                .any(|kid| !kids.insert(kid))
            {
                return Err(format!("issuer {}: key IDs must be unique", config.issuer));
            }
            let issuer = Issuer {
                config: config.clone(),
                keys,
            };
            if issuers.insert(config.issuer.clone(), issuer).is_some() {
                return Err(format!("issuer {} is configured twice", config.issuer));
            }
        }
        Ok(issuers)
    }

    /// Verifies `token`'s signature with the key its issuer configured, and returns the claims it
    /// signed. Nothing else about the token is checked here.
    pub(crate) fn verify_signature(&self, token: &str) -> Result<Signed, Rejection> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(Rejection::Malformed);
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| Rejection::Malformed)?;
        if header.crit.is_some() {
            return Err(Rejection::Malformed);
        }
        // The claims are read here only to find the issuer whose key must verify the token.
        // Nothing in them is trusted until `decode` below has verified the signature.
        let unverified: Map<String, Value> = jsonwebtoken::dangerous::insecure_decode_claims(token)
            .map_err(|_| Rejection::Malformed)?;
        let issuers = self
            .issuers
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let issuer = unverified
            .get("iss")
            .and_then(Value::as_str)
            .and_then(|iss| issuers.get(iss))
            .ok_or(Rejection::UnknownIssuer)?;
        let key = match header.kid.as_deref() {
            Some(kid) => issuer
                .keys
                .iter()
                .find(|key| key.kid.as_deref() == Some(kid)),
            None if issuer.keys.len() == 1 => issuer.keys.first(),
            None => None,
        }
        .ok_or(Rejection::UnknownKey)?;
        let mut validation = Validation::new(key.algorithm);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        let verified = jsonwebtoken::decode::<Map<String, Value>>(token, &key.key, &validation)
            .map_err(|error| match error.kind() {
                ErrorKind::InvalidSignature
                | ErrorKind::InvalidAlgorithm
                | ErrorKind::InvalidEcdsaKey
                | ErrorKind::InvalidEddsaKey
                | ErrorKind::InvalidRsaKey(_)
                | ErrorKind::Provider(_) => Rejection::BadSignature,
                _ => Rejection::Malformed,
            })?;
        Ok(Signed {
            issuer: issuer.config.issuer.clone(),
            claims: verified.claims,
        })
    }

    /// Verifies `token` at time `now`, in seconds since the Unix epoch, and records its ID.
    pub(crate) fn verify(&self, token: &str, now: u64) -> Result<Verified, Rejection> {
        let signed = self.verify_signature(token)?;
        if signed.claims.contains_key("cnf") {
            return Err(Rejection::ProofRequired);
        }
        let issuers = self
            .issuers
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let config = &issuers
            .get(&signed.issuer)
            .ok_or(Rejection::UnknownIssuer)?
            .config;
        let claims = &signed.claims;
        let expires_at = check_claims(claims, config, now)?;
        let token_id = match claims.get("jti") {
            Some(Value::String(id)) if !id.is_empty() && id.len() <= MAX_TOKEN_ID_BYTES => {
                Some(id.clone())
            }
            Some(_) => return Err(Rejection::Malformed),
            None if config.require_jti => return Err(Rejection::MissingClaim),
            None => None,
        };
        let subject = match claims.get("sub") {
            Some(Value::String(subject)) => Some(subject.clone()),
            Some(_) => return Err(Rejection::Malformed),
            None => None,
        };
        if let Some(id) = &token_id {
            let mut recorded = self
                .recorded
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let key = (config.issuer.clone(), id.clone());
            if recorded.contains_key(&key) {
                return Err(Rejection::Reused);
            }
            if recorded.len() >= MAX_RECORDED_TOKEN_IDS {
                recorded.retain(|_, expiry| expiry.saturating_add(LEEWAY_SECONDS) >= now);
                if recorded.len() >= MAX_RECORDED_TOKEN_IDS {
                    return Err(Rejection::TooManyRecordedTokens);
                }
            }
            recorded.insert(key, expires_at);
        }
        Ok(Verified {
            issuer: config.issuer.clone(),
            subject,
            token_id,
            expires_at,
        })
    }

    /// Forgets the token ID `verify` recorded for a token whose admission did not complete, so the
    /// token can be presented again.
    pub(crate) fn release(&self, verified: &Verified) {
        if let Some(id) = &verified.token_id {
            self.recorded
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&(verified.issuer.clone(), id.clone()));
        }
    }
}

/// Checks `aud`, `exp`, `iat`, `nbf`, the lifetime limit and the issuer's required claims, and
/// returns `exp`. The times must be whole numbers of seconds.
fn check_claims(
    claims: &Map<String, Value>,
    config: &IssuerConfig,
    now: u64,
) -> Result<u64, Rejection> {
    let audience_matches = match claims.get("aud") {
        Some(Value::String(audience)) => audience == &config.audience,
        Some(Value::Array(audiences)) => audiences
            .iter()
            .any(|audience| audience.as_str() == Some(config.audience.as_str())),
        _ => false,
    };
    if !audience_matches {
        return Err(Rejection::WrongAudience);
    }
    let time = |name: &str| {
        claims
            .get(name)
            .map(|value| value.as_u64().ok_or(Rejection::Malformed))
    };
    let expires_at = time("exp").ok_or(Rejection::MissingClaim)??;
    // Without `iat` there is no lifetime to limit, so it is required.
    let issued_at = time("iat").ok_or(Rejection::MissingClaim)??;
    if expires_at <= issued_at {
        return Err(Rejection::Malformed);
    }
    if now > expires_at.saturating_add(LEEWAY_SECONDS) {
        return Err(Rejection::Expired);
    }
    if issued_at > now.saturating_add(LEEWAY_SECONDS) {
        return Err(Rejection::NotYetValid);
    }
    if let Some(not_before) = time("nbf").transpose()?
        && not_before > now.saturating_add(LEEWAY_SECONDS)
    {
        return Err(Rejection::NotYetValid);
    }
    if expires_at - issued_at > config.max_lifetime_seconds {
        return Err(Rejection::LifetimeTooLong);
    }
    for (name, expected) in &config.required_claims {
        match claims.get(name) {
            None => return Err(Rejection::MissingClaim),
            Some(value) if value.as_str() != Some(expected.as_str()) => {
                return Err(Rejection::ClaimMismatch);
            }
            Some(_) => {}
        }
    }
    Ok(expires_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair},
    };
    use serde_json::json;

    enum Signer {
        Ed25519(Ed25519KeyPair),
        Es256(EcdsaKeyPair),
    }

    impl Signer {
        fn ed25519() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            Self::Ed25519(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
        }

        fn es256() -> Self {
            let rng = SystemRandom::new();
            let algorithm = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(algorithm, &rng).unwrap();
            Self::Es256(EcdsaKeyPair::from_pkcs8(algorithm, pkcs8.as_ref(), &rng).unwrap())
        }

        fn jwk(&self, kid: &str) -> Value {
            match self {
                Self::Ed25519(pair) => json!({"kty": "OKP", "crv": "Ed25519", "kid": kid,
                    "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}),
                Self::Es256(pair) => {
                    let point = pair.public_key().as_ref();
                    json!({"kty": "EC", "crv": "P-256", "kid": kid,
                        "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
                        "y": URL_SAFE_NO_PAD.encode(&point[33..65])})
                }
            }
        }

        fn alg(&self) -> &'static str {
            match self {
                Self::Ed25519(_) => "EdDSA",
                Self::Es256(_) => "ES256",
            }
        }

        fn token(&self, header: Value, claims: Value) -> String {
            let signed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            let signature = match self {
                Self::Ed25519(pair) => pair.sign(signed.as_bytes()).as_ref().to_vec(),
                Self::Es256(pair) => pair
                    .sign(&SystemRandom::new(), signed.as_bytes())
                    .unwrap()
                    .as_ref()
                    .to_vec(),
            };
            format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
        }

        fn sign(&self, kid: &str, claims: Value) -> String {
            self.token(json!({"alg": self.alg(), "kid": kid, "typ": "JWT"}), claims)
        }
    }

    const NOW: u64 = 1_800_000_000;

    fn issuer(name: &str, keys: Vec<Value>) -> IssuerConfig {
        serde_json::from_value(json!({
            "issuer": name,
            "audience": "gateway.example",
            "keys": {"keys": keys},
            "max_lifetime_seconds": 600,
            "required_claims": {"project": "project-1"},
            "require_jti": true
        }))
        .unwrap()
    }

    fn claims() -> Value {
        json!({"iss": "https://issuer.example", "sub": "workload-a"})
    }

    fn token_claims(jti: &str) -> Value {
        json!({"iss": "https://issuer.example", "aud": "gateway.example", "sub": "workload-a",
            "project": "project-1", "iat": NOW - 10, "exp": NOW + 290, "jti": jti})
    }

    fn without(mut claims: Value, name: &str) -> Value {
        claims.as_object_mut().unwrap().remove(name);
        claims
    }

    fn with(mut claims: Value, name: &str, value: Value) -> Value {
        claims[name] = value;
        claims
    }

    // An RSA-2048 public key and a token it signed (RS256, kid "r1"), made with openssl for this
    // test only; the private key was not kept.
    const RSA_N: &str = concat!(
        "sdEzKNVJhmJzQe7Qld2lKICoh0bPybRDGVZGdwSUKGpzsJc6Lx2nFupthqDAjCF-SFM5EbVY",
        "BX1l6Ey--Q8owLhsgbSIWZvW4xWogxLqcDmalmpk-IunnVx65EhT2MwrHRcaaPoUd-rlQLx5",
        "bfKuZ4R2D_vNEkCN8_KSAqoEUPjM___b0Ba9arIyhtM0AwdY1tbP-RgX-k7oZ9Mb6tRriKlA",
        "-Nt12oplKZyiaZ82BsOxcVU0NqqKtM1ZtYEXshxV5C5o9PTKWvh9utQokCLLync5IFxO0XJf",
        "y7_sfUIlmcbUj8QSfnzADTsSse4ohnolXyNLSt2BioWC39_GYPDJmw",
    );
    const RSA_TOKEN: &str = concat!(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6InIxIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczov",
        "L2lzc3Vlci5leGFtcGxlIiwic3ViIjoid29ya2xvYWQtYSJ9.g2PjZtK8FWhT2mpMsqVM7Cc",
        "Cn_9-MHwp85_SRDOwJCkI_0M4INJhe1m0Zd3RmLJqVdW8iCwLdxp6JmJYX4kBECaKXzPWDGb",
        "k3peG_Q4_fLd0cE5ruAZ-J_pffzxTGKyPpQx3xMAX2fajgP-54Sqt7KFEWoKgG1426EuSGNI",
        "n7a1-ounBHG7kA_IvNx1DJ6Z4PJkDMvZOkXfaOjyeAusvuxepsBVDxB810FeQgB72qLyVdjb",
        "PZHszQ4wNBWweBtNgpFQ5EPSSLyiGVKuyWqYVaECPZ_zoH7yVq5FfloGPSoCLTDFg139LEVR",
        "-N42z2tlFdXkjJzMa-9Hfha7cjmiy1w",
    );

    #[test]
    fn verifies_eddsa_es256_and_rs256_signatures() {
        for signer in [Signer::ed25519(), Signer::es256()] {
            let verifier =
                Verifier::new(&[issuer("https://issuer.example", vec![signer.jwk("k1")])]).unwrap();
            let token = signer.sign("k1", claims());
            let signed = verifier.verify_signature(&token).unwrap();
            assert_eq!(signed.issuer, "https://issuer.example");
            assert_eq!(signed.claims.get("sub"), Some(&json!("workload-a")));
        }
        let rsa = json!({"kty": "RSA", "kid": "r1", "n": RSA_N, "e": "AQAB"});
        let verifier = Verifier::new(&[issuer("https://issuer.example", vec![rsa])]).unwrap();
        let signed = verifier.verify_signature(RSA_TOKEN).unwrap();
        assert_eq!(signed.claims.get("sub"), Some(&json!("workload-a")));
    }

    #[test]
    fn refuses_tokens_that_fail_any_check() {
        let signer = Signer::ed25519();
        let other = Signer::ed25519();
        let verifier =
            Verifier::new(&[issuer("https://issuer.example", vec![signer.jwk("k1")])]).unwrap();
        let oversize = with(claims(), "padding", json!("x".repeat(MAX_TOKEN_BYTES)));
        let cases = [
            (other.sign("k1", claims()), Rejection::BadSignature),
            (signer.sign("k2", claims()), Rejection::UnknownKey),
            (
                signer.sign("k1", with(claims(), "iss", json!("https://other.example"))),
                Rejection::UnknownIssuer,
            ),
            (
                signer.token(json!({"alg": "ES256", "kid": "k1"}), claims()),
                Rejection::BadSignature,
            ),
            (
                signer.token(json!({"alg": "none", "kid": "k1"}), claims()),
                Rejection::Malformed,
            ),
            (
                signer.token(
                    json!({"alg": "EdDSA", "kid": "k1", "crit": ["x"]}),
                    claims(),
                ),
                Rejection::Malformed,
            ),
            (signer.sign("k1", oversize), Rejection::Malformed),
            ("not.a.token".to_owned(), Rejection::Malformed),
            ("only-one-part".to_owned(), Rejection::Malformed),
        ];
        for (token, expected) in cases {
            assert_eq!(verifier.verify_signature(&token), Err(expected));
        }
    }

    #[test]
    fn selects_the_key_by_kid_or_the_only_key() {
        let first = Signer::ed25519();
        let second = Signer::es256();
        let verifier = Verifier::new(&[issuer(
            "https://issuer.example",
            vec![first.jwk("k1"), second.jwk("k2")],
        )])
        .unwrap();
        assert!(
            verifier
                .verify_signature(&second.sign("k2", claims()))
                .is_ok()
        );
        let without_kid = first.token(json!({"alg": "EdDSA"}), claims());
        assert_eq!(
            verifier.verify_signature(&without_kid),
            Err(Rejection::UnknownKey)
        );
        let single =
            Verifier::new(&[issuer("https://issuer.example", vec![first.jwk("k1")])]).unwrap();
        assert!(single.verify_signature(&without_kid).is_ok());
    }

    #[test]
    fn rejects_unusable_configuration() {
        let signer = Signer::ed25519();
        let mut wrong_alg = signer.jwk("k1");
        wrong_alg["alg"] = json!("RS256");
        let short_rsa = json!({"kty": "RSA", "kid": "r1", "n": URL_SAFE_NO_PAD.encode([7u8; 128]),
            "e": URL_SAFE_NO_PAD.encode([1u8, 0, 1])});
        let mut encryption = signer.jwk("k1");
        encryption["use"] = json!("enc");
        let shared_secret =
            json!({"kty": "oct", "kid": "s1", "k": URL_SAFE_NO_PAD.encode([5u8; 32])});
        let p384 = json!({"kty": "EC", "crv": "P-384", "kid": "e1",
            "x": URL_SAFE_NO_PAD.encode([1u8; 48]), "y": URL_SAFE_NO_PAD.encode([2u8; 48])});
        let x25519 = json!({"kty": "OKP", "crv": "X25519", "kid": "x1",
            "x": URL_SAFE_NO_PAD.encode([3u8; 32])});
        let mut secret_member = signer.jwk("k1");
        secret_member["d"] = json!(URL_SAFE_NO_PAD.encode([4u8; 32]));
        let mut shared_member = signer.jwk("k1");
        shared_member["k"] = json!(URL_SAFE_NO_PAD.encode([4u8; 32]));
        let other_primes = json!({"kty": "RSA", "kid": "r1", "n": RSA_N, "e": "AQAB",
            "oth": [{"r": "AQAB", "d": "AQAB", "t": "AQAB"}]});
        let no_exponent = json!({"kty": "RSA", "kid": "r1", "n": RSA_N, "e": ""});
        for keys in [
            vec![],
            vec![wrong_alg],
            vec![short_rsa],
            vec![encryption],
            vec![shared_secret],
            vec![p384],
            vec![x25519],
            vec![secret_member],
            vec![shared_member],
            vec![other_primes],
            vec![no_exponent],
            vec![signer.jwk("k1"), Signer::es256().jwk("k1")],
        ] {
            assert!(
                Verifier::new(&[issuer("https://issuer.example", keys.clone())]).is_err(),
                "{keys:?}"
            );
        }
        // One unusable key refuses the whole configuration, every issuer included.
        let usable = issuer("https://usable.example", vec![signer.jwk("k1")]);
        let mut leaked = signer.jwk("k2");
        leaked["d"] = json!(URL_SAFE_NO_PAD.encode([4u8; 32]));
        let unusable = issuer("https://unusable.example", vec![leaked]);
        assert!(Verifier::new(&[usable.clone(), unusable]).is_err());
        assert!(Verifier::new(&[usable.clone(), usable]).is_err());
    }

    #[test]
    fn rejection_reasons_are_fixed_text() {
        for (rejection, text) in [
            (Rejection::Malformed, "malformed"),
            (Rejection::UnknownIssuer, "unknown_issuer"),
            (Rejection::UnknownKey, "unknown_key"),
            (Rejection::BadSignature, "bad_signature"),
            (Rejection::WrongAudience, "wrong_audience"),
            (Rejection::Expired, "expired"),
            (Rejection::NotYetValid, "not_yet_valid"),
            (Rejection::LifetimeTooLong, "lifetime_too_long"),
            (Rejection::MissingClaim, "missing_claim"),
            (Rejection::ClaimMismatch, "claim_mismatch"),
            (Rejection::Reused, "reused"),
            (Rejection::TooManyRecordedTokens, "too_many_recorded_tokens"),
            (Rejection::ProofRequired, "proof_required"),
        ] {
            assert_eq!(rejection.to_string(), text);
        }
    }

    #[test]
    fn accepts_a_token_with_an_id_once() {
        for signer in [Signer::ed25519(), Signer::es256()] {
            let verifier =
                Verifier::new(&[issuer("https://issuer.example", vec![signer.jwk("k1")])]).unwrap();
            let token = signer.sign("k1", token_claims("one"));
            assert_eq!(
                verifier.verify(&token, NOW),
                Ok(Verified {
                    issuer: "https://issuer.example".into(),
                    subject: Some("workload-a".into()),
                    token_id: Some("one".into()),
                    expires_at: NOW + 290,
                })
            );
            assert_eq!(verifier.verify(&token, NOW), Err(Rejection::Reused));
        }
    }

    #[test]
    fn refuses_tokens_whose_claims_fail_any_check() {
        let signer = Signer::ed25519();
        let verifier =
            Verifier::new(&[issuer("https://issuer.example", vec![signer.jwk("k1")])]).unwrap();
        let cases = [
            (
                with(token_claims("a"), "aud", json!("other.example")),
                Rejection::WrongAudience,
            ),
            (without(token_claims("b"), "aud"), Rejection::WrongAudience),
            (
                with(
                    with(token_claims("c"), "iat", json!(NOW - 100)),
                    "exp",
                    json!(NOW - 31),
                ),
                Rejection::Expired,
            ),
            (
                with(token_claims("d"), "iat", json!(NOW + 60)),
                Rejection::NotYetValid,
            ),
            (
                with(token_claims("e"), "nbf", json!(NOW + 60)),
                Rejection::NotYetValid,
            ),
            (
                with(token_claims("f"), "exp", json!(NOW + 700)),
                Rejection::LifetimeTooLong,
            ),
            (
                with(token_claims("g"), "project", json!("project-2")),
                Rejection::ClaimMismatch,
            ),
            (
                with(token_claims("h"), "project", Value::Null),
                Rejection::ClaimMismatch,
            ),
            (
                without(token_claims("i"), "project"),
                Rejection::MissingClaim,
            ),
            (without(token_claims("j"), "iat"), Rejection::MissingClaim),
            (without(token_claims("k"), "exp"), Rejection::MissingClaim),
            (
                with(token_claims("l"), "exp", json!(NOW - 10)),
                Rejection::Malformed,
            ),
            (
                with(token_claims("m"), "exp", json!(1.8e9)),
                Rejection::Malformed,
            ),
            (
                with(token_claims("n"), "iat", json!("yesterday")),
                Rejection::Malformed,
            ),
            (
                with(token_claims("o"), "nbf", json!(-1)),
                Rejection::Malformed,
            ),
            (
                with(token_claims("p"), "jti", json!("x".repeat(257))),
                Rejection::Malformed,
            ),
            (
                with(token_claims("q"), "jti", json!(7)),
                Rejection::Malformed,
            ),
            (
                with(token_claims("r"), "jti", json!("")),
                Rejection::Malformed,
            ),
            (
                with(token_claims("s"), "sub", json!(7)),
                Rejection::Malformed,
            ),
            (
                with(token_claims("t"), "cnf", json!({"jwk": signer.jwk("k9")})),
                Rejection::ProofRequired,
            ),
            (without(token_claims("u"), "jti"), Rejection::MissingClaim),
        ];
        for (claims, expected) in cases {
            assert_eq!(
                verifier.verify(&signer.sign("k1", claims.clone()), NOW),
                Err(expected),
                "{claims}"
            );
        }
        // A signature failure is refused before any claim is checked.
        let forged = Signer::ed25519().sign("k1", token_claims("v"));
        assert_eq!(verifier.verify(&forged, NOW), Err(Rejection::BadSignature));
    }

    #[test]
    fn a_refused_token_does_not_spend_its_id_and_a_released_one_can_return() {
        let signer = Signer::ed25519();
        let verifier =
            Verifier::new(&[issuer("https://issuer.example", vec![signer.jwk("k1")])]).unwrap();
        let wrong_project = with(token_claims("shared"), "project", json!("project-2"));
        assert_eq!(
            verifier.verify(&signer.sign("k1", wrong_project), NOW),
            Err(Rejection::ClaimMismatch)
        );
        let token = signer.sign("k1", token_claims("shared"));
        let verified = verifier.verify(&token, NOW).unwrap();
        assert_eq!(verifier.verify(&token, NOW), Err(Rejection::Reused));
        verifier.release(&verified);
        assert!(verifier.verify(&token, NOW).is_ok());
    }

    #[test]
    fn a_token_without_an_id_is_accepted_again_when_ids_are_optional() {
        let signer = Signer::ed25519();
        let mut config = issuer("https://issuer.example", vec![signer.jwk("k1")]);
        config.require_jti = false;
        let verifier = Verifier::new(&[config]).unwrap();
        let token = signer.sign("k1", without(token_claims("unused"), "jti"));
        assert!(verifier.verify(&token, NOW).is_ok());
        assert!(verifier.verify(&token, NOW).is_ok());
    }

    #[test]
    fn the_id_record_refuses_new_ids_only_while_it_is_full_of_unexpired_ones() {
        let signer = Signer::ed25519();
        let verifier =
            Verifier::new(&[issuer("https://issuer.example", vec![signer.jwk("k1")])]).unwrap();
        let fill = |expiry: u64| {
            let mut recorded = verifier.recorded.lock().unwrap();
            recorded.clear();
            for index in 0..MAX_RECORDED_TOKEN_IDS {
                recorded.insert(("https://issuer.example".into(), index.to_string()), expiry);
            }
        };
        fill(NOW + 300);
        assert_eq!(
            verifier.verify(&signer.sign("k1", token_claims("new")), NOW),
            Err(Rejection::TooManyRecordedTokens)
        );
        fill(NOW - LEEWAY_SECONDS - 1);
        assert!(
            verifier
                .verify(&signer.sign("k1", token_claims("new")), NOW)
                .is_ok()
        );
        assert_eq!(verifier.recorded.lock().unwrap().len(), 1);
    }

    #[test]
    fn audience_may_be_a_list() {
        let signer = Signer::es256();
        let verifier =
            Verifier::new(&[issuer("https://issuer.example", vec![signer.jwk("k1")])]).unwrap();
        let listed = with(
            token_claims("a"),
            "aud",
            json!(["other.example", "gateway.example"]),
        );
        assert!(verifier.verify(&signer.sign("k1", listed), NOW).is_ok());
    }

    #[test]
    fn rejects_an_issuer_without_an_audience_or_a_lifetime() {
        let signer = Signer::ed25519();
        let mut no_audience = issuer("https://issuer.example", vec![signer.jwk("k1")]);
        no_audience.audience = String::new();
        let mut no_lifetime = issuer("https://issuer.example", vec![signer.jwk("k1")]);
        no_lifetime.max_lifetime_seconds = 0;
        assert!(Verifier::new(&[no_audience]).is_err());
        assert!(Verifier::new(&[no_lifetime]).is_err());
    }
}
