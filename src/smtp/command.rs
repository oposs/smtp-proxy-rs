//! One SMTP command line -> Command. Mirrors the Perl CommandParser: the
//! verb is letters only, the argument is separated by exactly one space,
//! and the line must end in CRLF. Anything else is a malformed command,
//! and the line is consumed so that the next one can be reached.
use crate::smtp::params::{Param, parse_params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Ehlo {
        domain: String,
    },
    Helo {
        domain: String,
    },
    Noop,
    Quit,
    StartTls,
    Data,
    Rset,
    Auth {
        mechanism: String,
        initial: Option<String>,
    },
    Mail {
        from: String,
        params: Vec<Param>,
    },
    Rcpt {
        to: String,
        params: Vec<Param>,
    },
    Vrfy {
        string: String,
    },
}

impl Command {
    pub fn verb(&self) -> &'static str {
        match self {
            Command::Ehlo { .. } => "EHLO",
            Command::Helo { .. } => "HELO",
            Command::Noop => "NOOP",
            Command::Quit => "QUIT",
            Command::StartTls => "STARTTLS",
            Command::Data => "DATA",
            Command::Rset => "RSET",
            Command::Auth { .. } => "AUTH",
            Command::Mail { .. } => "MAIL",
            Command::Rcpt { .. } => "RCPT",
            Command::Vrfy { .. } => "VRFY",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandError {
    pub code: u16,
    pub text: &'static str,
}

const fn err(code: u16, text: &'static str) -> CommandError {
    CommandError { code, text }
}

/// Removes and returns the first line, terminator included.
pub fn take_line(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let end = memchr::memchr(b'\n', buf)? + 1;
    let line = buf[..end].to_vec();
    buf.drain(..end);
    Some(line)
}

pub fn parse_command(line: &[u8]) -> Result<Command, CommandError> {
    let malformed = err(500, "malformed command");
    let body = line.strip_suffix(b"\r\n").ok_or(malformed.clone())?;
    if body.contains(&b'\r') {
        return Err(malformed);
    }
    let verb_len = body.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    if verb_len == 0 {
        return Err(malformed);
    }
    let verb = std::str::from_utf8(&body[..verb_len])
        .unwrap()
        .to_ascii_uppercase();
    let args: Option<&str> = match &body[verb_len..] {
        [] => None,
        [b' ', rest @ ..] => Some(std::str::from_utf8(rest).map_err(|_| malformed.clone())?),
        _ => return Err(malformed),
    };

    match verb.as_str() {
        "EHLO" | "HELO" => {
            let domain = args
                .filter(|a| !a.is_empty())
                .ok_or(err(501, "domain required"))?;
            Ok(if verb == "EHLO" {
                Command::Ehlo {
                    domain: domain.into(),
                }
            } else {
                Command::Helo {
                    domain: domain.into(),
                }
            })
        }
        "NOOP" => Ok(Command::Noop),
        "QUIT" | "STARTTLS" | "DATA" | "RSET" => {
            if args.is_some_and(|a| !a.is_empty()) {
                return Err(err(501, "no arguments allowed"));
            }
            Ok(match verb.as_str() {
                "QUIT" => Command::Quit,
                "STARTTLS" => Command::StartTls,
                "DATA" => Command::Data,
                _ => Command::Rset,
            })
        }
        "AUTH" => parse_auth(args),
        "MAIL" => parse_path(args, "FROM:", true)
            .map(|(from, params)| Command::Mail { from, params })
            .map_err(|kind| match kind {
                PathError::Arguments => err(501, "invalid MAIL arguments"),
                PathError::Parameters => err(501, "invalid MAIL parameters"),
            }),
        "RCPT" => parse_path(args, "TO:", false)
            .map(|(to, params)| Command::Rcpt { to, params })
            .map_err(|kind| match kind {
                PathError::Arguments => err(501, "invalid RCPT arguments"),
                PathError::Parameters => err(501, "invalid RCPT parameters"),
            }),
        "VRFY" => {
            let string = args
                .filter(|a| !a.is_empty())
                .ok_or(err(501, "string required"))?;
            Ok(Command::Vrfy {
                string: string.into(),
            })
        }
        _ => Err(err(502, "unknown command")),
    }
}

/// RFC 4954 section 4: a mechanism name is 1 to 20 characters of upper
/// alpha, digit, hyphen and underscore, matched without regard to case.
fn parse_auth(args: Option<&str>) -> Result<Command, CommandError> {
    let invalid = err(501, "invalid AUTH arguments");
    let args = args.ok_or(invalid.clone())?;
    let (mechanism, initial) = match args.split_once(' ') {
        Some((m, rest)) => (m, Some(rest)),
        None => (args, None),
    };
    let ok_len = (1..=20).contains(&mechanism.len());
    let ok_chars = mechanism
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok_len || !ok_chars {
        return Err(invalid);
    }
    Ok(Command::Auth {
        mechanism: mechanism.to_ascii_uppercase(),
        initial: initial.filter(|s| !s.is_empty()).map(String::from),
    })
}

enum PathError {
    Arguments,
    Parameters,
}

/// `FROM:<addr> [params]` / `TO:<addr> [params]`, keyword case-insensitive,
/// optional whitespace after the colon. `allow_empty` admits the null
/// return path `<>`.
fn parse_path(
    args: Option<&str>,
    keyword: &str,
    allow_empty: bool,
) -> Result<(String, Vec<Param>), PathError> {
    let args = args.ok_or(PathError::Arguments)?;
    // Compared as bytes rather than as `args[..keyword.len()]`: `args` is
    // whatever UTF-8 the client sent, and slicing a `&str` at a byte index
    // panics when that index falls inside a multi-byte character -- which
    // `MAIL FROM\u{00d6}` does, before any state or auth check has run.
    // `keyword` is ASCII, so once it matches, `keyword.len()` is a character
    // boundary and the slice below cannot panic.
    match args.as_bytes().get(..keyword.len()) {
        Some(head) if head.eq_ignore_ascii_case(keyword.as_bytes()) => {}
        _ => return Err(PathError::Arguments),
    }
    let rest = args[keyword.len()..].trim_start();
    let rest = rest.strip_prefix('<').ok_or(PathError::Arguments)?;
    let close = rest.find('>').ok_or(PathError::Arguments)?;
    let address = &rest[..close];
    if address.is_empty() && !allow_empty {
        return Err(PathError::Arguments);
    }
    let tail = &rest[close + 1..];
    let params = if tail.is_empty() {
        Vec::new()
    } else if let Some(param_text) = tail.strip_prefix(' ') {
        if param_text.is_empty() {
            Vec::new()
        } else {
            parse_params(param_text).ok_or(PathError::Parameters)?
        }
    } else {
        return Err(PathError::Arguments);
    };
    Ok((address.to_string(), params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smtp::params::Param;

    fn parse(s: &str) -> Result<Command, CommandError> {
        parse_command(format!("{s}\r\n").as_bytes())
    }

    fn p(k: &str, v: Option<&str>) -> Param {
        Param {
            keyword: k.into(),
            value: v.map(String::from),
        }
    }

    /// A multi-byte character straddling the keyword's byte length used to
    /// panic the session task: `args[..keyword.len()]` cuts a `&str` at a
    /// byte index, and `parse_command` runs before any state or auth check,
    /// so any client that can open the port could reach it.
    #[test]
    fn multibyte_argument_is_refused_not_panicked() {
        for line in [
            "MAIL FROM\u{00d6}",
            "MAIL FROM\u{00d6}:<sender@foobar.com>",
            "RCPT T\u{00d6}",
            "MAIL FROM:<a@b.com> \u{00d6}",
            "MAIL \u{00d6}",
        ] {
            assert!(parse(line).is_err(), "{line}");
        }
    }

    #[test]
    fn mail_keyword_is_case_insensitive() {
        for args in [
            "FROM:<sender@foobar.com>",
            "From:<sender@foobar.com>",
            "From: <sender@foobar.com>",
            "from:<sender@foobar.com>",
            "FrOm:<sender@foobar.com>",
        ] {
            assert_eq!(
                parse(&format!("MAIL {args}")),
                Ok(Command::Mail {
                    from: "sender@foobar.com".into(),
                    params: vec![]
                }),
                "{args}"
            );
        }
        assert_eq!(
            parse("MAIL From:<sender@foobar.com> SIZE=1234"),
            Ok(Command::Mail {
                from: "sender@foobar.com".into(),
                params: vec![p("SIZE", Some("1234"))]
            })
        );
    }

    #[test]
    fn mail_rejections() {
        for args in ["From:", "SENDER:<sender@foobar.com>", ""] {
            assert_eq!(
                parse(format!("MAIL {args}").trim_end()),
                Err(CommandError {
                    code: 501,
                    text: "invalid MAIL arguments"
                }),
                "{args:?}"
            );
        }
        assert_eq!(
            parse("MAIL FROM:<a@b.com> NOTIFY="),
            Err(CommandError {
                code: 501,
                text: "invalid MAIL parameters"
            })
        );
    }

    #[test]
    fn rcpt_keyword_is_case_insensitive() {
        for args in [
            "TO:<rcpt@foobaz.com>",
            "To:<rcpt@foobaz.com>",
            "to:<rcpt@foobaz.com>",
        ] {
            assert_eq!(
                parse(&format!("RCPT {args}")),
                Ok(Command::Rcpt {
                    to: "rcpt@foobaz.com".into(),
                    params: vec![]
                })
            );
        }
        assert_eq!(
            parse("RCPT tO:<rcpt@foobaz.com> NOTIFY=NEVER"),
            Ok(Command::Rcpt {
                to: "rcpt@foobaz.com".into(),
                params: vec![p("NOTIFY", Some("NEVER"))]
            })
        );
        assert_eq!(parse("RCPT FOR:<rcpt@foobaz.com>").unwrap_err().code, 501);
        assert_eq!(parse("RCPT").unwrap_err().code, 501);
    }

    #[test]
    fn dsn_parameters_survive() {
        assert_eq!(
            parse("RCPT TO:<a@b.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;a@b.com"),
            Ok(Command::Rcpt {
                to: "a@b.com".into(),
                params: vec![
                    p("NOTIFY", Some("SUCCESS,FAILURE")),
                    p("ORCPT", Some("rfc822;a@b.com"))
                ]
            })
        );
        assert_eq!(
            parse("MAIL FROM:<a@b.com> RET=HDRS ENVID=QQ314159"),
            Ok(Command::Mail {
                from: "a@b.com".into(),
                params: vec![p("RET", Some("HDRS")), p("ENVID", Some("QQ314159"))]
            })
        );
    }

    #[test]
    fn null_return_path() {
        assert_eq!(
            parse("MAIL FROM:<>"),
            Ok(Command::Mail {
                from: String::new(),
                params: vec![]
            })
        );
        assert_eq!(
            parse("MAIL FROM:<> RET=FULL"),
            Ok(Command::Mail {
                from: String::new(),
                params: vec![p("RET", Some("FULL"))]
            })
        );
        assert_eq!(
            parse("RCPT TO:<>"),
            Err(CommandError {
                code: 501,
                text: "invalid RCPT arguments"
            })
        );
    }

    #[test]
    fn valueless_and_zero_parameters() {
        assert_eq!(
            parse("RCPT TO:<a@b.com> SMTPUTF8"),
            Ok(Command::Rcpt {
                to: "a@b.com".into(),
                params: vec![p("SMTPUTF8", None)]
            })
        );
        assert_eq!(
            parse("MAIL FROM:<a@b.com> 0"),
            Ok(Command::Mail {
                from: "a@b.com".into(),
                params: vec![p("0", None)]
            })
        );
        assert_eq!(
            parse("RCPT TO:<a@b.com> 0"),
            Ok(Command::Rcpt {
                to: "a@b.com".into(),
                params: vec![p("0", None)]
            })
        );
    }

    #[test]
    fn malformed_parameters_draw_501() {
        for bad in [
            "NOTIFY=",
            "=SUCCESS",
            "NOTIFY=A=B",
            "-BAD=1",
            "X=caf\u{e9}",
            "X=del\x7f",
            "X=\u{ff}",
        ] {
            assert_eq!(
                parse(&format!("RCPT TO:<a@b.com> {bad}")).unwrap_err().code,
                501,
                "{bad:?}"
            );
        }
        assert!(parse("RCPT TO:<a@b.com> X=~!$%^&*()_+{}|:\"<>?").is_ok());
    }

    #[test]
    fn minimum_command_set() {
        assert_eq!(
            parse("HELO client.example.com"),
            Ok(Command::Helo {
                domain: "client.example.com".into()
            })
        );
        assert_eq!(
            parse("EHLO client.example.com"),
            Ok(Command::Ehlo {
                domain: "client.example.com".into()
            })
        );
        assert_eq!(parse("NOOP"), Ok(Command::Noop));
        assert_eq!(parse("NOOP keep alive"), Ok(Command::Noop));
        assert_eq!(parse("QUIT"), Ok(Command::Quit));
        assert_eq!(parse("RSET"), Ok(Command::Rset));
        assert_eq!(parse("DATA"), Ok(Command::Data));
        assert_eq!(parse("STARTTLS"), Ok(Command::StartTls));
        assert_eq!(parse("starttls"), Ok(Command::StartTls));
        assert_eq!(
            parse("VRFY someone@example.com"),
            Ok(Command::Vrfy {
                string: "someone@example.com".into()
            })
        );
    }

    #[test]
    fn no_argument_commands_reject_arguments() {
        for verb in ["QUIT", "STARTTLS", "DATA", "RSET"] {
            assert_eq!(
                parse(&format!("{verb} x")),
                Err(CommandError {
                    code: 501,
                    text: "no arguments allowed"
                })
            );
        }
    }

    #[test]
    fn mandatory_arguments() {
        assert_eq!(
            parse("EHLO"),
            Err(CommandError {
                code: 501,
                text: "domain required"
            })
        );
        assert_eq!(
            parse("HELO"),
            Err(CommandError {
                code: 501,
                text: "domain required"
            })
        );
        assert_eq!(
            parse("VRFY"),
            Err(CommandError {
                code: 501,
                text: "string required"
            })
        );
    }

    #[test]
    fn auth_mechanism_is_normalised() {
        for line in [
            "AUTH PLAIN dGVzdA==",
            "AUTH plain dGVzdA==",
            "AUTH PlAiN dGVzdA==",
        ] {
            assert_eq!(
                parse(line),
                Ok(Command::Auth {
                    mechanism: "PLAIN".into(),
                    initial: Some("dGVzdA==".into())
                })
            );
        }
        assert_eq!(
            parse("AUTH login"),
            Ok(Command::Auth {
                mechanism: "LOGIN".into(),
                initial: None
            })
        );
        assert_eq!(
            parse("AUTH CRAM-MD5"),
            Ok(Command::Auth {
                mechanism: "CRAM-MD5".into(),
                initial: None
            })
        );
        assert_eq!(
            parse("AUTH SCRAM-SHA-256 abcd"),
            Ok(Command::Auth {
                mechanism: "SCRAM-SHA-256".into(),
                initial: Some("abcd".into())
            })
        );
        assert_eq!(
            parse("AUTH X_MECH"),
            Ok(Command::Auth {
                mechanism: "X_MECH".into(),
                initial: None
            })
        );
        assert_eq!(
            parse("AUTH"),
            Err(CommandError {
                code: 501,
                text: "invalid AUTH arguments"
            })
        );
        assert_eq!(
            parse(&format!("AUTH {}", "A".repeat(21))).unwrap_err().code,
            501
        );
    }

    #[test]
    fn unknown_verbs_draw_502() {
        assert_eq!(
            parse("PING"),
            Err(CommandError {
                code: 502,
                text: "unknown command"
            })
        );
        assert_eq!(parse("PING hello").unwrap_err().code, 502);
    }

    #[test]
    fn malformed_lines_draw_500() {
        for bad in ["MAIL FROM:<a\rb>\r\n", "\r\n", "NOOP\n", " NOOP\r\n"] {
            assert_eq!(
                parse_command(bad.as_bytes()),
                Err(CommandError {
                    code: 500,
                    text: "malformed command"
                }),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn take_line_splits_pipelined_commands() {
        let mut buf = b"MAIL FROM:<a@b.com>\r\nRCPT TO:<c@d.com>\r\nDATA\r\n".to_vec();
        assert_eq!(take_line(&mut buf).unwrap(), b"MAIL FROM:<a@b.com>\r\n");
        assert_eq!(buf, b"RCPT TO:<c@d.com>\r\nDATA\r\n");
        assert_eq!(take_line(&mut buf).unwrap(), b"RCPT TO:<c@d.com>\r\n");
        assert_eq!(take_line(&mut buf).unwrap(), b"DATA\r\n");
        assert!(buf.is_empty());
    }

    #[test]
    fn take_line_holds_an_incomplete_line() {
        let mut buf = b"MAIL FRO".to_vec();
        assert_eq!(take_line(&mut buf), None);
        assert_eq!(buf, b"MAIL FRO");
    }

    #[test]
    fn commands_after_a_rejected_line_are_still_reached() {
        let mut buf = b"MAIL FROM:<a\rb>\r\nNOOP\r\nRSET\r\n".to_vec();
        let mut seen = Vec::new();
        while let Some(line) = take_line(&mut buf) {
            seen.push(match parse_command(&line) {
                Ok(c) => c.verb().to_string(),
                Err(e) => e.text.to_string(),
            });
        }
        assert_eq!(seen, ["malformed command", "NOOP", "RSET"]);
        assert!(buf.is_empty());
    }
}
