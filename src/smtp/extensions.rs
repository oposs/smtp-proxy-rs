//! The extension keywords an EHLO reply announces.
use std::collections::HashSet;

pub fn parse_extensions(ehlo_reply: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for line in ehlo_reply.split(['\r', '\n']) {
        let b = line.as_bytes();
        if b.len() < 4 || !b[..3].iter().all(u8::is_ascii_digit) || !(b[3] == b'-' || b[3] == b' ')
        {
            continue;
        }
        if let Some(word) = line[4..].split_ascii_whitespace().next() {
            set.insert(word.to_ascii_uppercase());
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_are_collected_and_uppercased() {
        let set = parse_extensions(
            "250-recording.upstream\r\n250-dsn\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n",
        );
        assert!(set.contains("DSN"));
        assert!(set.contains("SIZE"));
        assert!(set.contains("STARTTLS"));
        assert!(!set.contains("10240000"));
    }

    #[test]
    fn lines_without_a_code_are_ignored() {
        assert!(parse_extensions("garbage\r\n").is_empty());
        assert!(parse_extensions("").is_empty());
    }
}
