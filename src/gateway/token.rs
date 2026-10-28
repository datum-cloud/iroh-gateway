//! Verification of bearer token signatures against configured issuers.
//!
//! A token is a JWS compact serialization (a signed JWT). Each configured issuer has its own keys,
//! checked when the configuration loads; one unusable key refuses the whole configuration. The
//! signing algorithm is fixed by the selected key, never taken from the token alone.
//!
//! Signatures are verified with `jsonwebtoken`. The key checks here run before it sees a key,
//! because it accepts shared-secret keys and does not check curves.
//!
//! Rejections carry fixed reasons only: nothing from the token is ever placed in an error or log.

// Nothing calls the verifier until token admission is added; that change removes this.
#![allow(dead_code)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, errors::ErrorKind};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::RwLock,
};

const MAX_TOKEN_BYTES: usize = 8 * 1024;
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
    /// Verification keys, as a JSON Web Key Set.
    pub keys: JwkSet,
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

/// Why a token was refused. The reasons are fixed strings and carry no token content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    Malformed,
    UnknownIssuer,
    UnknownKey,
    BadSignature,
}

impl Rejection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnknownIssuer => "unknown_issuer",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
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

/// Verifies token signatures against the configured issuers.
pub(crate) struct Verifier {
    issuers: RwLock<HashMap<String, Issuer>>,
}

impl Verifier {
    pub(crate) fn new(configs: &[IssuerConfig]) -> Result<Self, String> {
        Ok(Self {
            issuers: RwLock::new(Self::issuers(configs)?),
        })
    }

    fn issuers(configs: &[IssuerConfig]) -> Result<HashMap<String, Issuer>, String> {
        let mut issuers = HashMap::new();
        for config in configs {
            if config.issuer.is_empty() {
                return Err("an issuer needs a non-empty issuer".into());
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

    fn issuer(name: &str, keys: Vec<Value>) -> IssuerConfig {
        serde_json::from_value(json!({"issuer": name, "keys": {"keys": keys}})).unwrap()
    }

    fn claims() -> Value {
        json!({"iss": "https://issuer.example", "sub": "workload-a"})
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
        ] {
            assert_eq!(rejection.to_string(), text);
        }
    }
}
