//! Reply formatting. RFC 5321 4.5.3.1.5: a reply line is at most 512 octets
//! including the code, the separator and CRLF. Reply text is not ours (it
//! comes from the upstream and from the API), so every character outside
//! tab and printable ASCII is folded to a space: CR and LF would break the
//! framing and let text from upstream inject a forged reply line; ESC and
//! friends would be executed by the terminal of whoever tails the smtplog.

pub const MAX_REPLY_LINE: usize = 512;
const MAX_TEXT: usize = MAX_REPLY_LINE - "250 ".len() - "\r\n".len();

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplyError {
    #[error("Invalid response code '{0}'")]
    InvalidCode(u16),
    #[error("Must have at least one response line")]
    NoLines,
}

/// Folds every run of characters outside tab and printable ASCII into one
/// space, strips trailing whitespace, and truncates to fit a reply line.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_run = false;
    for c in text.chars() {
        let printable = c == '\t' || ('\u{20}'..='\u{7e}').contains(&c);
        if printable {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push(' ');
            in_run = true;
        }
    }
    let trimmed = out.trim_end();
    if trimmed.len() > MAX_TEXT {
        let mut s = trimmed[..MAX_TEXT - 3].to_string();
        s.push_str("...");
        s
    } else {
        trimmed.to_string()
    }
}

pub fn format_reply(code: u16, lines: &[&str]) -> Result<String, ReplyError> {
    if !(200..=599).contains(&code) {
        return Err(ReplyError::InvalidCode(code));
    }
    if lines.is_empty() {
        return Err(ReplyError::NoLines);
    }
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        let sep = if i + 1 == lines.len() { ' ' } else { '-' };
        out.push_str(&format!("{code}{sep}{}\r\n", sanitize(line)));
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            lines: vec![text.into()],
        }
    }

    pub fn multi(code: u16, lines: Vec<String>) -> Self {
        Self { code, lines }
    }

    /// The wire form.
    ///
    /// **A code outside `200..=599` panics here rather than reaching the
    /// client, so every caller has to have established that its code is in
    /// range before it builds the `Reply`.** There is no recovery this far
    /// down: the session task dies and the client is answered nothing at all,
    /// which is worse than any wrong-but-sendable code would have been.
    ///
    /// Most codes are literals in this crate and satisfy that for free. One
    /// does not: a code derived from outside this process -- an upstream's
    /// own reply -- can be any three digits, and it is the deriving code's
    /// job to constrain it. See [`crate::relay::RelayError::client_code`],
    /// which is the only such path today.
    pub fn wire(&self) -> String {
        let refs: Vec<&str> = self.lines.iter().map(String::as_str).collect();
        format_reply(self.code, &refs)
            .expect("callers constrain a reply code to 200..=599 before building a Reply")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_body(reply: &str) -> &str {
        &reply[..reply.len() - 2]
    }

    #[test]
    fn single_line() {
        assert_eq!(format_reply(250, &["OK"]).unwrap(), "250 OK\r\n");
    }

    #[test]
    fn multi_line() {
        assert_eq!(
            format_reply(250, &["greeting", "STARTTLS", "DSN"]).unwrap(),
            "250-greeting\r\n250-STARTTLS\r\n250 DSN\r\n"
        );
    }

    #[test]
    fn trailing_newline_is_removed() {
        let r = format_reply(550, &["Requested action not taken: nope\n"]).unwrap();
        assert_eq!(r, "550 Requested action not taken: nope\r\n");
        assert!(!line_body(&r).contains(['\r', '\n']));
    }

    #[test]
    fn embedded_crlf_is_folded() {
        assert_eq!(
            format_reply(550, &["first\r\nsecond"]).unwrap(),
            "550 first second\r\n"
        );
    }

    #[test]
    fn cannot_inject_a_reply_line() {
        let r = format_reply(550, &["rejected\r\n250 OK, go ahead"]).unwrap();
        assert_eq!(r, "550 rejected 250 OK, go ahead\r\n");
        assert_eq!(r.matches("\r\n").count(), 1);
    }

    #[test]
    fn bare_cr_is_folded() {
        assert_eq!(
            format_reply(550, &["carriage\rreturn"]).unwrap(),
            "550 carriage return\r\n"
        );
    }

    #[test]
    fn continuation_lines_are_sanitised() {
        assert_eq!(
            format_reply(250, &["one\r\ntwo", "three"]).unwrap(),
            "250-one two\r\n250 three\r\n"
        );
    }

    #[test]
    fn overlong_line_is_truncated_to_512_octets() {
        let long = format_reply(550, &["x".repeat(1000).as_str()]).unwrap();
        assert!(long.len() <= MAX_REPLY_LINE);
        assert!(long.starts_with("550 xxx"));
        assert!(long.ends_with("...\r\n"));
    }

    #[test]
    fn bad_code_is_an_error() {
        assert!(matches!(
            format_reply(9999, &["nope"]),
            Err(ReplyError::InvalidCode(9999))
        ));
        assert!(matches!(
            format_reply(100, &["nope"]),
            Err(ReplyError::InvalidCode(100))
        ));
        assert!(matches!(format_reply(250, &[]), Err(ReplyError::NoLines)));
    }

    #[test]
    fn control_characters_are_folded() {
        let r = format_reply(550, &["esc\x1b[31mred\x00nul\x07bell"]).unwrap();
        assert!(
            !line_body(&r)
                .bytes()
                .any(|b| b != b'\t' && !(0x20..=0x7e).contains(&b))
        );
        assert_eq!(r, "550 esc [31mred nul bell\r\n");
    }

    #[test]
    fn wide_characters_do_not_reach_the_wire() {
        let r = format_reply(550, &["caf\u{e9} \u{263a} smile"]).unwrap();
        assert!(r.is_ascii());
        assert!(
            !line_body(&r)
                .bytes()
                .any(|b| b != b'\t' && !(0x20..=0x7e).contains(&b))
        );
        let long = format_reply(550, &["\u{263a}".repeat(1000).as_str()]).unwrap();
        assert!(long.len() <= MAX_REPLY_LINE);
    }

    #[test]
    fn reply_struct_formats_the_same() {
        assert_eq!(Reply::new(250, "OK").wire(), "250 OK\r\n");
        assert_eq!(
            Reply::multi(250, vec!["a".into(), "b".into()]).wire(),
            "250-a\r\n250 b\r\n"
        );
    }
}
