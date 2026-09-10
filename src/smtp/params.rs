//! RFC 5321 4.1.2 esmtp-param lists.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Param {
    pub keyword: String,
    pub value: Option<String>,
}

fn is_keyword_start(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_keyword_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// esmtp-value: printable ASCII excluding "=" and space.
fn is_value_char(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && b != b'='
}

/// Returns None if any parameter is malformed. Dropping a bad one silently
/// would tell the client we honoured something we discarded.
pub fn parse_params(text: &str) -> Option<Vec<Param>> {
    let mut out = Vec::new();
    for word in text.split_ascii_whitespace() {
        let (keyword, value) = match word.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (word, None),
        };
        let kb = keyword.as_bytes();
        if kb.is_empty() || !is_keyword_start(kb[0]) || !kb.iter().all(|&b| is_keyword_char(b)) {
            return None;
        }
        if let Some(v) = value
            && (v.is_empty() || !v.bytes().all(is_value_char))
        {
            return None;
        }
        out.push(Param {
            keyword: keyword.to_string(),
            value: value.map(String::from),
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(k: &str, v: Option<&str>) -> Param {
        Param {
            keyword: k.into(),
            value: v.map(String::from),
        }
    }

    #[test]
    fn dsn_parameters_parse() {
        assert_eq!(
            parse_params("NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;a@b.com"),
            Some(vec![
                p("NOTIFY", Some("SUCCESS,FAILURE")),
                p("ORCPT", Some("rfc822;a@b.com"))
            ])
        );
    }

    #[test]
    fn valueless_parameter_has_no_value() {
        assert_eq!(parse_params("SMTPUTF8"), Some(vec![p("SMTPUTF8", None)]));
    }

    #[test]
    fn keyword_zero_is_kept() {
        assert_eq!(parse_params("0"), Some(vec![p("0", None)]));
    }

    #[test]
    fn malformed_parameters_are_rejected_as_a_whole() {
        for bad in [
            "NOTIFY=",
            "=SUCCESS",
            "NOTIFY=A=B",
            "-BAD=1",
            "X=caf\u{e9}",
            "X=del\x7f",
        ] {
            assert_eq!(parse_params(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn printable_ascii_value_is_accepted() {
        assert!(parse_params("X=~!$%^&*()_+{}|:\"<>?").is_some());
    }

    #[test]
    fn serialises_with_null_value() {
        let json = serde_json::to_string(&p("SMTPUTF8", None)).unwrap();
        assert_eq!(json, r#"{"keyword":"SMTPUTF8","value":null}"#);
    }
}
