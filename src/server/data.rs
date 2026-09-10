//! Reads the lines of a DATA payload: undoes dot stuffing, splits headers
//! from body at the first empty line, ends at the lone dot, and enforces
//! the size cap without holding more than the cap in memory.

pub enum DataEvent {
    HeadersComplete(String),
    MessageComplete(Vec<u8>),
    TooLarge,
}

pub struct DataReader {
    max_size: usize,
    headers_done: bool,
    headers: Vec<u8>,
    body: Vec<u8>,
    size: usize,
    too_large: bool,
}

fn is_empty_line(line: &[u8]) -> bool {
    line == b"\r\n" || line == b"\n"
}

fn is_terminator(line: &[u8]) -> bool {
    line == b".\r\n" || line == b".\n"
}

impl DataReader {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            headers_done: false,
            headers: Vec::new(),
            body: Vec::new(),
            size: 0,
            too_large: false,
        }
    }

    /// `line` includes its terminator.
    pub fn push_line(&mut self, line: &[u8]) -> Option<DataEvent> {
        if is_terminator(line) {
            if self.too_large {
                return Some(DataEvent::TooLarge);
            }
            return Some(DataEvent::MessageComplete(std::mem::take(&mut self.body)));
        }
        if !self.headers_done && is_empty_line(line) {
            self.headers_done = true;
            let headers = String::from_utf8_lossy(&std::mem::take(&mut self.headers)).into_owned();
            return Some(DataEvent::HeadersComplete(headers));
        }
        let unstuffed = line.strip_prefix(b".").unwrap_or(line);
        self.size += unstuffed.len();
        if self.size > self.max_size {
            self.too_large = true;
            self.headers.clear();
            self.body.clear();
            return None;
        }
        if self.headers_done {
            self.body.extend_from_slice(unstuffed);
        } else {
            self.headers.extend_from_slice(unstuffed);
        }
        None
    }

    /// The header block, if the terminator arrived before any empty line.
    pub fn take_pending_headers(&mut self) -> Option<String> {
        if self.headers_done {
            return None;
        }
        self.headers_done = true;
        Some(String::from_utf8_lossy(&std::mem::take(&mut self.headers)).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(reader: &mut DataReader, text: &str) -> Vec<DataEvent> {
        let mut events = Vec::new();
        let mut rest = text;
        while let Some(i) = rest.find('\n') {
            let (line, tail) = rest.split_at(i + 1);
            if let Some(e) = reader.push_line(line.as_bytes()) {
                events.push(e);
            }
            rest = tail;
        }
        events
    }

    #[test]
    fn headers_then_body() {
        let mut r = DataReader::new(usize::MAX);
        let events = feed(
            &mut r,
            "From: a@b.com\r\nSubject: hi\r\n\r\nline one\r\n.\r\n",
        );
        assert_eq!(events.len(), 2);
        assert!(
            matches!(&events[0], DataEvent::HeadersComplete(h) if h == "From: a@b.com\r\nSubject: hi\r\n")
        );
        assert!(matches!(&events[1], DataEvent::MessageComplete(b) if b == b"line one\r\n"));
        assert!(r.take_pending_headers().is_none());
    }

    #[test]
    fn dot_stuffing_is_undone_in_headers_and_body() {
        let mut r = DataReader::new(usize::MAX);
        let events = feed(&mut r, "..X-Odd: yes\r\n\r\n..\r\n...\r\n.\r\n");
        assert!(matches!(&events[0], DataEvent::HeadersComplete(h) if h == ".X-Odd: yes\r\n"));
        assert!(matches!(&events[1], DataEvent::MessageComplete(b) if b == b".\r\n..\r\n"));
    }

    #[test]
    fn dot_before_any_empty_line_means_headers_only() {
        let mut r = DataReader::new(usize::MAX);
        let events = feed(&mut r, "Subject: x\r\n.\r\n");
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], DataEvent::MessageComplete(b) if b.is_empty()));
        assert_eq!(r.take_pending_headers().as_deref(), Some("Subject: x\r\n"));
    }

    #[test]
    fn bare_lf_terminators_are_accepted() {
        let mut r = DataReader::new(usize::MAX);
        let events = feed(&mut r, "A: 1\n\nbody\n.\n");
        assert!(matches!(&events[0], DataEvent::HeadersComplete(h) if h == "A: 1\n"));
        assert!(matches!(&events[1], DataEvent::MessageComplete(b) if b == b"body\n"));
    }

    #[test]
    fn size_cap_discards_and_reports() {
        let mut r = DataReader::new(20);
        let events = feed(
            &mut r,
            "A: 1\r\n\r\n0123456789\r\n0123456789\r\n0123456789\r\n.\r\n",
        );
        assert!(matches!(&events[0], DataEvent::HeadersComplete(_)));
        assert!(matches!(&events[1], DataEvent::TooLarge));
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn size_cap_counts_headers_too() {
        // The cap (5) is crossed while the header block itself is still being
        // accumulated, before the blank line is even seen. HeadersComplete is
        // still emitted when the blank line arrives, but carrying an empty
        // string: the over-cap header bytes were discarded as they came in,
        // per spec 4.7 (the cap counts headers plus body).
        let mut r = DataReader::new(5);
        let events = feed(&mut r, "Subject: long enough\r\n\r\n.\r\n");
        assert!(matches!(&events[0], DataEvent::HeadersComplete(_)));
        assert!(matches!(&events[1], DataEvent::TooLarge));
    }
}
