//! AUTH PLAIN (RFC 4616) and AUTH LOGIN decoding.
use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub authzid: String,
    pub authcid: String,
    pub password: String,
}

pub const USERNAME_CHALLENGE: &str = "VXNlcm5hbWU6";
pub const PASSWORD_CHALLENGE: &str = "UGFzc3dvcmQ6";

const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub fn decode_lenient(b64: &str) -> Option<Vec<u8>> {
    LENIENT.decode(b64.trim()).ok()
}

pub fn decode_plain(b64: &str) -> Option<Credentials> {
    let raw = decode_lenient(b64)?;
    let mut parts = raw.split(|b| *b == 0);
    let authzid = String::from_utf8_lossy(parts.next()?).into_owned();
    let authcid = String::from_utf8_lossy(parts.next()?).into_owned();
    let password = String::from_utf8_lossy(parts.next()?).into_owned();
    Some(Credentials {
        authzid,
        authcid,
        password,
    })
}

pub fn decode_login(user_b64: &str, pass_b64: &str) -> Option<Credentials> {
    Some(Credentials {
        authzid: String::new(),
        authcid: String::from_utf8_lossy(&decode_lenient(user_b64)?).into_owned(),
        password: String::from_utf8_lossy(&decode_lenient(pass_b64)?).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(s: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn plain_splits_on_nul() {
        let c = decode_plain(&b64(b"zid\0user\0pass")).unwrap();
        assert_eq!(
            c,
            Credentials {
                authzid: "zid".into(),
                authcid: "user".into(),
                password: "pass".into()
            }
        );
        let c = decode_plain(&b64(b"\0user\0pass")).unwrap();
        assert_eq!(c.authzid, "");
    }

    #[test]
    fn plain_rejects_garbage() {
        assert!(decode_plain("not base64!").is_none());
        assert!(decode_plain(&b64(b"user\0pass")).is_none());
    }

    #[test]
    fn login_pairs_username_and_password() {
        let c = decode_login(&b64(b"user"), &b64(b"pass")).unwrap();
        assert_eq!(
            c,
            Credentials {
                authzid: String::new(),
                authcid: "user".into(),
                password: "pass".into()
            }
        );
    }

    #[test]
    fn padding_is_optional() {
        assert_eq!(decode_lenient("dGVzdA").unwrap(), b"test");
        assert_eq!(decode_lenient("dGVzdA==").unwrap(), b"test");
    }

    #[test]
    fn challenges_are_the_rfc_strings() {
        assert_eq!(decode_lenient(USERNAME_CHALLENGE).unwrap(), b"Username:");
        assert_eq!(decode_lenient(PASSWORD_CHALLENGE).unwrap(), b"Password:");
    }
}
