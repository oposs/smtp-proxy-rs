//! The extension keywords an EHLO reply announces, with their parameters.
use std::collections::HashMap;

/// One EHLO reply's extensions: keyword (uppercased) to the rest of the
/// line, which is empty when the keyword stands alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extensions(HashMap<String, String>);

impl Extensions {
    pub fn contains(&self, keyword: &str) -> bool {
        self.0.contains_key(&keyword.to_ascii_uppercase())
    }

    /// The SIZE limit the upstream states, if it states a usable one.
    ///
    /// `None` covers three cases a caller must treat alike -- SIZE absent,
    /// SIZE with no parseable number, and RFC 1870's `SIZE 0`, which means
    /// "no fixed maximum". A limit of zero bytes is never what was meant.
    pub fn size(&self) -> Option<usize> {
        self.0
            .get("SIZE")?
            .split_ascii_whitespace()
            .next()?
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
    }
}

pub fn parse_extensions(ehlo_reply: &str) -> Extensions {
    let mut map = HashMap::new();
    for line in ehlo_reply.split(['\r', '\n']) {
        let b = line.as_bytes();
        if b.len() < 4 || !b[..3].iter().all(u8::is_ascii_digit) || !(b[3] == b'-' || b[3] == b' ')
        {
            continue;
        }
        // Trim before slicing: split_ascii_whitespace() skips leading
        // whitespace before returning `word`, so `word.len()` is only a
        // valid cut point into `rest` when `word` starts at byte 0 of it.
        // Trimming first makes that true, and also keeps the cut on a char
        // boundary when the keyword itself is non-ASCII.
        let rest = line[4..].trim_start();
        let mut words = rest.split_ascii_whitespace();
        if let Some(word) = words.next() {
            let params = rest[word.len()..].trim_start().to_string();
            map.insert(word.to_ascii_uppercase(), params);
        }
    }
    Extensions(map)
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
        assert!(set.contains("STARTTLS"));
        assert!(!set.contains("PIPELINING"));
        // A parameter token must never become a keyword in its own right.
        assert!(!set.contains("10240000"));
    }

    #[test]
    fn garbage_is_ignored() {
        assert!(!parse_extensions("garbage\r\n").contains("DSN"));
        assert!(!parse_extensions("garbage\r\n").contains("GARBAGE"));
        assert!(!parse_extensions("").contains("DSN"));
    }

    /// A stray space (or tab) between the `250-`/`250 ` separator and the
    /// keyword must not shift the params slice into the middle of the
    /// keyword. Covers the whole whitespace-position family the separator
    /// can carry: none, one leading space, a tab, and multiple internal
    /// spaces between keyword and value.
    #[test]
    fn stray_whitespace_around_the_keyword_does_not_corrupt_params() {
        assert_eq!(
            parse_extensions("250-SIZE 10240000\r\n").size(),
            Some(10_240_000)
        );
        assert_eq!(
            parse_extensions("250- SIZE 10240000\r\n").size(),
            Some(10_240_000)
        );
        assert_eq!(
            parse_extensions("250-\tSIZE 10240000\r\n").size(),
            Some(10_240_000)
        );
        assert_eq!(
            parse_extensions("250-SIZE   10240000\r\n").size(),
            Some(10_240_000)
        );
    }

    /// A leading space before a non-ASCII keyword must not panic: the old
    /// code sliced `rest` at `word.len()`, a byte offset computed against a
    /// trimmed copy but applied to the untrimmed string, which lands mid
    /// character whenever the keyword itself is multi-byte UTF-8. This must
    /// return, not unwind -- reachable from an upstream server's EHLO reply,
    /// a panic here would take down a whole client session or the
    /// background upstream probe.
    #[test]
    fn stray_whitespace_before_a_non_ascii_keyword_does_not_panic() {
        let e = parse_extensions("250- SIZÉ 10\r\n");
        assert!(e.contains("SIZÉ"));
    }

    #[test]
    fn size_carries_its_value() {
        let e = parse_extensions("250-SIZE 10240000\r\n250 DSN\r\n");
        assert_eq!(e.size(), Some(10_240_000));
    }

    #[test]
    fn size_absent_is_none() {
        assert_eq!(parse_extensions("250 DSN\r\n").size(), None);
    }

    /// RFC 1870: a SIZE with no number, or an unparsable one, announces the
    /// extension without stating a limit. Treated as "no limit stated",
    /// never as zero-length.
    #[test]
    fn size_without_a_usable_number_is_none() {
        assert_eq!(parse_extensions("250 SIZE\r\n").size(), None);
        assert_eq!(parse_extensions("250 SIZE lots\r\n").size(), None);
    }

    /// RFC 1870 gives 0 the meaning "no fixed maximum", so it must not reach
    /// a caller as a limit of zero bytes.
    #[test]
    fn size_zero_means_no_limit() {
        assert_eq!(parse_extensions("250 SIZE 0\r\n").size(), None);
    }
}
