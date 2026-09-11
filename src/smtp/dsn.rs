//! RFC 3461 gives each of its four parameters a grammar and two of them a
//! length limit. A server that announces DSN MUST answer 501 to a
//! syntactically invalid one (section 5.1), at the command that carried it.
use crate::smtp::params::Param;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsnCommand {
    Mail,
    Rcpt,
}

pub fn is_mail_dsn_keyword(k: &str) -> bool {
    k.eq_ignore_ascii_case("RET") || k.eq_ignore_ascii_case("ENVID")
}

pub fn is_rcpt_dsn_keyword(k: &str) -> bool {
    k.eq_ignore_ascii_case("NOTIFY") || k.eq_ignore_ascii_case("ORCPT")
}

/// RFC 3461 section 4: xtext is printable ASCII other than '+' and '=',
/// with anything else written as '+' followed by two hex digits.
fn is_xtext(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                if i + 2 >= b.len()
                    || !b[i + 1].is_ascii_hexdigit()
                    || !b[i + 2].is_ascii_hexdigit()
                {
                    return false;
                }
                i += 3;
            }
            0x21..=0x2a | 0x2c..=0x3c | 0x3e..=0x7e => i += 1,
            _ => return false,
        }
    }
    true
}

pub fn validate_dsn(params: &[Param], which: DsnCommand) -> Result<(), String> {
    let mut seen: Vec<String> = Vec::new();
    for p in params {
        let keyword = p.keyword.to_ascii_uppercase();
        let check: fn(Option<&str>) -> Result<(), String> = match (which, keyword.as_str()) {
            (DsnCommand::Mail, "RET") => check_ret,
            (DsnCommand::Mail, "ENVID") => check_envid,
            (DsnCommand::Rcpt, "NOTIFY") => check_notify,
            (DsnCommand::Rcpt, "ORCPT") => check_orcpt,
            _ => continue,
        };
        if seen.contains(&keyword) {
            return Err(format!("{keyword} given more than once"));
        }
        seen.push(keyword);
        check(p.value.as_deref())?;
    }
    Ok(())
}

fn check_ret(value: Option<&str>) -> Result<(), String> {
    match value {
        Some(v) if v.eq_ignore_ascii_case("FULL") || v.eq_ignore_ascii_case("HDRS") => Ok(()),
        _ => Err("RET requires a value of FULL or HDRS".into()),
    }
}

/// RFC 3461 4.4 caps the envelope id at 100 characters.
fn check_envid(value: Option<&str>) -> Result<(), String> {
    let v = value
        .filter(|v| !v.is_empty())
        .ok_or("ENVID requires a value")?;
    if v.len() > 100 {
        return Err("ENVID is limited to 100 characters".into());
    }
    if !is_xtext(v) {
        return Err("ENVID must be xtext".into());
    }
    Ok(())
}

/// RFC 3461 4.1: NEVER on its own, or one or more of SUCCESS, FAILURE, DELAY.
fn check_notify(value: Option<&str>) -> Result<(), String> {
    let v = value
        .filter(|v| !v.is_empty())
        .ok_or("NOTIFY requires a value")?;
    let items: Vec<&str> = v.split(',').collect();
    if items.iter().any(|i| i.is_empty()) {
        return Err("NOTIFY has an empty element".into());
    }
    let mut seen: Vec<String> = Vec::new();
    for item in &items {
        let upper = item.to_ascii_uppercase();
        if !matches!(upper.as_str(), "NEVER" | "SUCCESS" | "FAILURE" | "DELAY") {
            return Err(format!("NOTIFY value '{item}' is not recognised"));
        }
        if seen.contains(&upper) {
            return Err(format!("NOTIFY lists {upper} more than once"));
        }
        seen.push(upper);
    }
    if seen.iter().any(|s| s == "NEVER") && items.len() > 1 {
        return Err("NOTIFY=NEVER cannot be combined with other values".into());
    }
    Ok(())
}

/// RFC 3461 4.2: an address type, a semicolon and an xtext address, in at
/// most 500 characters.
fn check_orcpt(value: Option<&str>) -> Result<(), String> {
    let v = value
        .filter(|v| !v.is_empty())
        .ok_or("ORCPT requires a value")?;
    if v.len() > 500 {
        return Err("ORCPT is limited to 500 characters".into());
    }
    let bad_shape = "ORCPT must be an address type, a semicolon and an address";
    let (atype, address) = v.split_once(';').ok_or(bad_shape)?;
    let tb = atype.as_bytes();
    let type_ok = !tb.is_empty()
        && tb[0].is_ascii_alphanumeric()
        && tb.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-');
    if !type_ok || address.is_empty() {
        return Err(bad_shape.into());
    }
    if !is_xtext(address) {
        return Err("ORCPT address must be xtext".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smtp::params::parse_params;

    fn check(which: DsnCommand, text: &str) -> Result<(), String> {
        validate_dsn(&parse_params(text).unwrap(), which)
    }

    #[test]
    fn mail_parameters() {
        use DsnCommand::Mail;
        assert_eq!(
            check(Mail, "RET=PARTIAL"),
            Err("RET requires a value of FULL or HDRS".into())
        );
        assert_eq!(
            check(Mail, "RET"),
            Err("RET requires a value of FULL or HDRS".into())
        );
        assert_eq!(
            check(Mail, &format!("ENVID={}", "x".repeat(101))),
            Err("ENVID is limited to 100 characters".into())
        );
        assert_eq!(
            check(Mail, "ENVID=has+zz"),
            Err("ENVID must be xtext".into())
        );
        assert_eq!(
            check(Mail, "ENVID=one ENVID=two"),
            Err("ENVID given more than once".into())
        );
        assert_eq!(
            check(Mail, "RET=FULL RET=HDRS"),
            Err("RET given more than once".into())
        );
        assert_eq!(check(Mail, "RET=HDRS ENVID=QQ314159"), Ok(()));
        assert_eq!(check(Mail, "ret=hdrs"), Ok(()));
        assert_eq!(check(Mail, "SIZE=100 RET=FULL"), Ok(()));
    }

    #[test]
    fn rcpt_parameters() {
        use DsnCommand::Rcpt;
        assert_eq!(
            check(Rcpt, "NOTIFY=MAYBE"),
            Err("NOTIFY value 'MAYBE' is not recognised".into())
        );
        assert_eq!(
            check(Rcpt, "NOTIFY=NEVER,SUCCESS"),
            Err("NOTIFY=NEVER cannot be combined with other values".into())
        );
        assert_eq!(
            check(Rcpt, "NOTIFY=DELAY,DELAY"),
            Err("NOTIFY lists DELAY more than once".into())
        );
        assert_eq!(
            check(Rcpt, "NOTIFY=SUCCESS,"),
            Err("NOTIFY has an empty element".into())
        );
        assert_eq!(
            check(Rcpt, "ORCPT=nosemicolon"),
            Err("ORCPT must be an address type, a semicolon and an address".into())
        );
        assert_eq!(
            check(Rcpt, &format!("ORCPT=rfc822;{}", "x".repeat(500))),
            Err("ORCPT is limited to 500 characters".into())
        );
        assert_eq!(
            check(Rcpt, "NOTIFY=DELAY NOTIFY=NEVER"),
            Err("NOTIFY given more than once".into())
        );
        assert_eq!(
            check(Rcpt, "NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;c@d.com"),
            Ok(())
        );
        assert_eq!(check(Rcpt, "NOTIFY=NEVER"), Ok(()));
        assert_eq!(check(Rcpt, "ORCPT=rfc822;a+40b"), Ok(()));
    }

    #[test]
    fn keyword_helpers() {
        assert!(is_mail_dsn_keyword("ret") && is_mail_dsn_keyword("ENVID"));
        assert!(is_rcpt_dsn_keyword("notify") && is_rcpt_dsn_keyword("ORCPT"));
        assert!(!is_mail_dsn_keyword("NOTIFY") && !is_rcpt_dsn_keyword("SIZE"));
    }
}
