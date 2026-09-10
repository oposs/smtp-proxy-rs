//! The optional wire log: one line per SMTP line sent or received.
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

pub struct SmtpLog {
    file: Mutex<File>,
    credentials: bool,
}

pub fn format_entry(id: &str, timestamp: &str, sent: bool, line: &str) -> String {
    let leader = if sent { "<<<" } else { ">>>" };
    format!("{id} {timestamp} {leader} {line}\n")
}

/// `AUTH <mech> <secret>` -> `AUTH <mech> [REDACTED]`, matched on the raw
/// line because verb and mechanism are case-insensitive on the wire.
pub fn redact_auth_line(line: &str) -> String {
    let mut parts = line.splitn(3, char::is_whitespace);
    let (Some(verb), Some(mech), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return line.to_string();
    };
    if verb.eq_ignore_ascii_case("AUTH") && !mech.is_empty() && !rest.trim().is_empty() {
        let prefix_len = line.len() - rest.len();
        format!("{}[REDACTED]", &line[..prefix_len])
    } else {
        line.to_string()
    }
}

fn now() -> String {
    let z = jiff::Zoned::now();
    format!(
        "{} {:02}:{:02}:{:02}",
        z.date(),
        z.hour(),
        z.minute(),
        z.second()
    )
}

impl SmtpLog {
    pub fn open(path: &Path, credentials: bool) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            credentials,
        })
    }

    fn write(&self, id: &str, sent: bool, line: &str) {
        let entry = format_entry(id, &now(), sent, line.trim_end_matches(['\r', '\n']));
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(entry.as_bytes());
            let _ = f.flush();
        }
    }

    /// A command line from the client.
    pub fn received(&self, id: &str, line: &str) {
        let shown = if self.credentials {
            line.to_string()
        } else {
            redact_auth_line(line)
        };
        self.write(id, false, &shown);
    }

    /// An AUTH continuation line, which is entirely secret.
    pub fn received_auth_secret(&self, id: &str, line: &str) {
        let shown = if self.credentials { line } else { "[REDACTED]" };
        self.write(id, false, shown);
    }

    /// A reply as written to the wire; may hold several lines.
    pub fn sent(&self, id: &str, wire: &str) {
        for line in wire.split("\r\n").filter(|l| !l.is_empty()) {
            self.write(id, true, line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_arguments_are_redacted() {
        assert_eq!(
            redact_auth_line("AUTH PLAIN dXNlcgBwYXNz"),
            "AUTH PLAIN [REDACTED]"
        );
        assert_eq!(
            redact_auth_line("auth plain dXNlcgBwYXNz"),
            "auth plain [REDACTED]"
        );
        assert_eq!(redact_auth_line("AUTH LOGIN"), "AUTH LOGIN");
        assert_eq!(
            redact_auth_line("MAIL FROM:<a@b.com>"),
            "MAIL FROM:<a@b.com>"
        );
    }

    #[test]
    fn entry_layout() {
        assert_eq!(
            format_entry("abc", "2026-09-10 14:13:51", false, "EHLO x"),
            "abc 2026-09-10 14:13:51 >>> EHLO x\n"
        );
        assert_eq!(
            format_entry("abc", "2026-09-10 14:13:51", true, "250 OK"),
            "abc 2026-09-10 14:13:51 <<< 250 OK\n"
        );
    }

    #[test]
    fn file_round_trip_with_and_without_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("smtp.log");
        let log = SmtpLog::open(&path, false).unwrap();
        log.received("id1", "AUTH PLAIN c2VjcmV0");
        log.received_auth_secret("id1", "c2VjcmV0");
        log.sent("id1", "250-a\r\n250 b\r\n");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].ends_with(">>> AUTH PLAIN [REDACTED]"));
        assert!(lines[1].ends_with(">>> [REDACTED]"));
        assert!(lines[2].ends_with("<<< 250-a"));
        assert!(lines[3].ends_with("<<< 250 b"));

        let log = SmtpLog::open(&path, true).unwrap();
        log.received("id2", "AUTH PLAIN c2VjcmV0");
        log.received_auth_secret("id2", "c2VjcmV0");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(">>> AUTH PLAIN c2VjcmV0"));
        assert!(text.contains("id2 ") && text.lines().last().unwrap().ends_with(">>> c2VjcmV0"));
    }
}
