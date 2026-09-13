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

/// The most decoded bytes an AUTH username may have. Far above any real
/// username, far below anything that matters for memory.
///
/// **Divergence from the Perl, approved 2026-09-13.** The Perl applies no
/// length check at all, and neither did this proxy: the only bound on the
/// path was `MAX_COMMAND_BUFFER` (`server::session`) at 64 KiB, which exists
/// to stop a client that never sends a newline, so a single username could be
/// roughly 50 KiB. The username is the one unverified client-supplied string
/// the process *stores* -- `ratelimit` keys its buckets on it and holds them
/// for up to a prune window. `MAX_BUCKETS` bounds how many are held; this
/// bounds how big each one can be.
///
/// The password is deliberately not bounded. It is never retained, so it
/// costs one transient allocation per connection, itself bounded by
/// `--max_connections`.
const MAX_USERNAME: usize = 256;

pub fn decode_lenient(b64: &str) -> Option<Vec<u8>> {
    LENIENT.decode(b64.trim()).ok()
}

/// The decoded bytes, if there are not too many of them. Checked before the
/// lossy conversion, because a replacement character is three bytes where the
/// byte it stands for was one, and it is the decoded length that is bounded.
fn username(decoded: &[u8]) -> Option<String> {
    (decoded.len() <= MAX_USERNAME).then(|| String::from_utf8_lossy(decoded).into_owned())
}

pub fn decode_plain(b64: &str) -> Option<Credentials> {
    let raw = decode_lenient(b64)?;
    let mut parts = raw.split(|b| *b == 0);
    let authzid = String::from_utf8_lossy(parts.next()?).into_owned();
    let authcid = username(parts.next()?)?;
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
        authcid: username(&decode_lenient(user_b64)?)?,
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

    /// A username at the bound authenticates; one byte more does not, on
    /// both mechanisms. `None` is what `session::finish_auth` already turns
    /// into `535 Authentication credentials invalid`, so no reply text is
    /// added by the bound.
    #[test]
    fn an_over_long_username_does_not_decode() {
        let at_bound = "u".repeat(MAX_USERNAME);
        let over = "u".repeat(MAX_USERNAME + 1);

        let plain = |user: &str| decode_plain(&b64(format!("\0{user}\0pass").as_bytes()));
        assert_eq!(plain(&at_bound).unwrap().authcid, at_bound);
        assert!(plain(&over).is_none());

        let login = |user: &str| decode_login(&b64(user.as_bytes()), &b64(b"pass"));
        assert_eq!(login(&at_bound).unwrap().authcid, at_bound);
        assert!(login(&over).is_none());
    }

    /// The bound is on the decoded bytes, not on the characters they turn
    /// into: 100 invalid bytes become 100 replacement characters and 300
    /// bytes of `String`, and that is still a username well inside the
    /// bound. Bounding the lossy string instead would refuse it.
    #[test]
    fn the_bound_is_on_the_decoded_bytes() {
        let raw = [0xffu8; 100];
        let token = b64(&[b"\0".as_slice(), &raw, b"\0pass"].concat());
        let creds = decode_plain(&token).unwrap();
        assert!(
            creds.authcid.len() > MAX_USERNAME,
            "{}",
            creds.authcid.len()
        );
    }

    /// The password is not bounded: it is never retained.
    #[test]
    fn a_long_password_is_still_accepted() {
        let password = "p".repeat(4096);
        let creds = decode_plain(&b64(format!("\0user\0{password}").as_bytes())).unwrap();
        assert_eq!(creds.password, password);
        let creds = decode_login(&b64(b"user"), &b64(password.as_bytes())).unwrap();
        assert_eq!(creds.password, password);
    }

    #[test]
    fn challenges_are_the_rfc_strings() {
        assert_eq!(decode_lenient(USERNAME_CHALLENGE).unwrap(), b"Username:");
        assert_eq!(decode_lenient(PASSWORD_CHALLENGE).unwrap(), b"Password:");
    }
}
