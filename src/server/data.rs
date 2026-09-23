//! The two halves of a DATA payload. `HeaderCollector` holds the header
//! block whole -- it is parsed, so it has to be -- and bounds it with
//! `--max_header_size`. `BodyFramer` stages the body on its way to the
//! upstream and retains nothing beyond one write chunk.

/// The body is written upstream in pieces of this size, each under its own
/// timer. Spec 6 gives the relay an *inactivity* timeout, so what has to
/// hold is "some progress within the timeout", not "the whole body within
/// the timeout": a single deadline over the payload would abort a healthy
/// but merely slow upstream. At 64 KiB a chunk the 60 s default asks the
/// upstream for about 1 KB/s, which no working relay fails.
pub const WRITE_CHUNK: usize = 64 * 1024;

/// What a complete header line did to the block.
#[derive(Debug)]
pub enum HeaderEvent {
    /// The blank line arrived: here is the block, as the client sent it.
    /// Bytes rather than a `String`: a header may carry raw Latin-1, and
    /// what goes upstream has to be what arrived (`proxy.rs`, `RawHeader`).
    Complete(Vec<u8>),
    /// The lone dot arrived first, so the message is headers only. The
    /// block is still pending; `take_pending` hands it over.
    Terminator,
    /// The block crossed `--max_header_size`. What was collected is gone;
    /// the caller drains to the terminator and answers there.
    TooLarge,
}

/// Collects the header block, undoing the client's dot stuffing, until the
/// blank line that ends it -- or the terminator, when there is no body.
pub struct HeaderCollector {
    max_header_size: usize,
    headers: Vec<u8>,
    size: usize,
    too_large: bool,
    /// The block has been handed over, by `Complete` or by `take_pending`.
    delivered: bool,
}

/// The blank line that ends the header block.
fn is_empty_line(line: &[u8]) -> bool {
    line == b"\r\n" || line == b"\n"
}

/// The lone dot that ends the message. Only meaningful at a line start,
/// which is the caller's business to know.
pub fn is_terminator(line: &[u8]) -> bool {
    line == b".\r\n" || line == b".\n"
}

impl HeaderCollector {
    pub fn new(max_header_size: usize) -> Self {
        Self {
            max_header_size,
            headers: Vec::new(),
            size: 0,
            too_large: false,
            delivered: false,
        }
    }

    /// `line` includes its terminator.
    ///
    /// Three events end the block and hand the caller its next job:
    /// `Complete` at the blank line, `Terminator` when the lone dot arrives
    /// first, and `TooLarge` when the cap is crossed. A caller that keeps
    /// pushing afterwards is told what state the collector is in rather than
    /// starting it over: every line after `TooLarge` is `TooLarge` again, the
    /// terminator included, because a discarding collector has nothing else
    /// to say and the caller is draining to answer `552` itself (spec 6);
    /// and after `Complete` what arrives is body, which this type does not
    /// collect. Nothing accumulates on any of those paths.
    pub fn push_line(&mut self, line: &[u8]) -> Option<HeaderEvent> {
        if self.too_large {
            return Some(HeaderEvent::TooLarge);
        }
        if is_terminator(line) {
            return Some(HeaderEvent::Terminator);
        }
        if self.delivered {
            return None;
        }
        if is_empty_line(line) {
            self.delivered = true;
            return Some(HeaderEvent::Complete(std::mem::take(&mut self.headers)));
        }
        let unstuffed = line.strip_prefix(b".").unwrap_or(line);
        self.size += unstuffed.len();
        if self.size > self.max_header_size {
            self.mark_too_large();
            return Some(HeaderEvent::TooLarge);
        }
        self.headers.extend_from_slice(unstuffed);
        None
    }

    /// Bytes still allowed before the cap is crossed, or `None` once it has
    /// been crossed and the collector is discarding. A caller reading from a
    /// socket uses this to bound an incomplete line: those bytes count
    /// against the cap too, but `push_line` never gets to see them.
    pub fn remaining_capacity(&self) -> Option<usize> {
        if self.too_large {
            None
        } else {
            Some(self.max_header_size.saturating_sub(self.size))
        }
    }

    /// Enters discard mode without a complete line, for a caller that has
    /// watched the cap being crossed by bytes it is still buffering.
    /// Everything accumulated so far is dropped.
    pub fn mark_too_large(&mut self) {
        self.too_large = true;
        self.headers.clear();
    }

    /// The header block, when the terminator arrived before any blank line.
    /// `None` once the block has been handed over, and once the cap has been
    /// crossed: there is nothing left to hand over in either case.
    pub fn take_pending(&mut self) -> Option<Vec<u8>> {
        if self.delivered || self.too_large {
            return None;
        }
        self.delivered = true;
        Some(std::mem::take(&mut self.headers))
    }
}

/// One piece of body, on its way to the upstream.
#[derive(Debug)]
pub enum BodyPiece {
    /// Staged, not yet worth a write.
    Pending,
    /// The staging buffer filled: write this.
    Chunk(Vec<u8>),
    /// The lone dot. The body is over.
    Terminator,
}

/// Frames the body after the header block. Retains nothing beyond one
/// staging buffer of `WRITE_CHUNK` and, at most, a single held-back CR.
///
/// Body lines pass through **verbatim**: the proxy neither unstuffs nor
/// restuffs. Only the line *ending* is normalised to CRLF, which is the one
/// thing `normalize_and_stuff` did that the wire still needs. SMTP frames on
/// LF, so a CR with no LF after it is data and passes through untouched --
/// turning it into CRLF would split one body line into two and could hand
/// the upstream a `.\r\n` the client never sent (spec 5.1).
pub struct BodyFramer {
    out: Vec<u8>,
    /// True when the next byte begins a line. The terminator is meaningful
    /// only there -- and a multi-gigabyte line is self-evidently not a
    /// three-byte terminator.
    at_line_start: bool,
    /// A CR at the end of a piece: we cannot yet tell CRLF from a bare CR,
    /// so the byte waits for the next one rather than being guessed at. An
    /// LF arriving next makes it a line ending; anything else makes it data
    /// and it is written as the lone CR it is. It belongs to the framer and
    /// not to the piece, so `flush` leaves it alone.
    held_cr: bool,
}

impl BodyFramer {
    pub fn new() -> Self {
        Self {
            out: Vec::with_capacity(WRITE_CHUNK),
            at_line_start: true,
            held_cr: false,
        }
    }

    /// A complete line, its terminator included.
    ///
    /// The terminator is reported before anything is appended, so the dot
    /// never reaches the upstream. No CR can be stranded by that: holding
    /// one takes a partial line, which leaves the framer mid-line, and
    /// mid-line this reports no terminator.
    pub fn push(&mut self, line: &[u8]) -> BodyPiece {
        if self.at_line_start && is_terminator(line) {
            return BodyPiece::Terminator;
        }
        self.append(line);
        self.at_line_start = true;
        self.piece()
    }

    /// Bytes with no line ending in sight. The caller has hit its buffer
    /// bound, so these are staged as they are and the framer stays mid-line.
    pub fn push_partial(&mut self, bytes: &[u8]) -> BodyPiece {
        self.append(bytes);
        self.at_line_start = false;
        self.piece()
    }

    /// Whatever is staged, however little. The held CR is not part of it:
    /// it belongs to the bytes still to come.
    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// A write's worth of body, or nothing yet. Batching is the point: a
    /// piece per line would be one socket write per line.
    fn piece(&mut self) -> BodyPiece {
        if self.out.len() >= WRITE_CHUNK {
            BodyPiece::Chunk(std::mem::take(&mut self.out))
        } else {
            BodyPiece::Pending
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        let mut i = 0;
        if self.held_cr {
            self.held_cr = false;
            if bytes.first() == Some(&b'\n') {
                self.out.extend_from_slice(b"\r\n");
                i = 1;
            } else {
                // Nothing followed it, so it was never a line ending.
                self.out.push(b'\r');
            }
        }
        while i < bytes.len() {
            match bytes[i] {
                b'\r' if i + 1 == bytes.len() => {
                    self.held_cr = true;
                    i += 1;
                }
                b'\r' if bytes[i + 1] == b'\n' => {
                    self.out.extend_from_slice(b"\r\n");
                    i += 2;
                }
                b'\n' => {
                    self.out.extend_from_slice(b"\r\n");
                    i += 1;
                }
                b => {
                    self.out.push(b);
                    i += 1;
                }
            }
        }
    }
}

impl Default for BodyFramer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_end_at_the_blank_line() {
        let mut h = HeaderCollector::new(usize::MAX);
        assert!(h.push_line(b"A: 1\r\n").is_none());
        match h.push_line(b"\r\n") {
            Some(HeaderEvent::Complete(s)) => assert_eq!(s, b"A: 1\r\n"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_terminator_before_any_blank_line_is_a_header_only_message() {
        let mut h = HeaderCollector::new(usize::MAX);
        assert!(h.push_line(b"A: 1\r\n").is_none());
        assert!(matches!(
            h.push_line(b".\r\n"),
            Some(HeaderEvent::Terminator)
        ));
        assert_eq!(h.take_pending().unwrap(), b"A: 1\r\n");
    }

    #[test]
    fn headers_over_the_cap_report_too_large() {
        let mut h = HeaderCollector::new(8);
        assert!(matches!(
            h.push_line(b"A: aaaaaaaaaaaaaaaaaaaa\r\n"),
            Some(HeaderEvent::TooLarge)
        ));
    }

    /// The discarding state is stable: once the cap has been crossed every
    /// further line says so, the blank line and the terminator included, and
    /// nothing is collected on top of what was thrown away. The caller drains
    /// to the terminator itself and answers there.
    #[test]
    fn every_line_after_the_cap_reports_too_large() {
        let mut h = HeaderCollector::new(8);
        assert!(matches!(
            h.push_line(b"A: aaaaaaaaaaaaaaaaaaaa\r\n"),
            Some(HeaderEvent::TooLarge)
        ));
        assert!(matches!(
            h.push_line(b"B: 2\r\n"),
            Some(HeaderEvent::TooLarge)
        ));
        assert!(matches!(h.push_line(b"\r\n"), Some(HeaderEvent::TooLarge)));
        assert!(matches!(h.push_line(b".\r\n"), Some(HeaderEvent::TooLarge)));
        assert!(h.take_pending().is_none());
    }

    /// The block is handed over once. What follows the blank line is body,
    /// and the collector neither collects it nor offers a second block.
    ///
    /// The cap is what makes that visible: 6 bytes of header leave 2, so a
    /// 6 byte line counted on top of them would cross the cap and report
    /// `TooLarge`. Reporting nothing is the proof that nothing was counted.
    #[test]
    fn nothing_is_collected_after_the_block_has_been_handed_over() {
        let mut h = HeaderCollector::new(8);
        assert!(h.push_line(b"A: 1\r\n").is_none());
        assert!(matches!(
            h.push_line(b"\r\n"),
            Some(HeaderEvent::Complete(_))
        ));
        assert!(h.push_line(b"body\r\n").is_none());
        assert!(h.take_pending().is_none());
    }

    /// The header block is parsed by the proxy, so it is the one place that
    /// still has to undo the client's dot stuffing.
    #[test]
    fn dot_stuffing_is_undone_in_the_header_block() {
        let mut h = HeaderCollector::new(usize::MAX);
        assert!(h.push_line(b"..X-Odd: yes\r\n").is_none());
        match h.push_line(b"\r\n") {
            Some(HeaderEvent::Complete(s)) => assert_eq!(s, b".X-Odd: yes\r\n"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bare_lf_line_terminators_are_accepted() {
        let mut h = HeaderCollector::new(usize::MAX);
        assert!(h.push_line(b"A: 1\n").is_none());
        match h.push_line(b"\n") {
            Some(HeaderEvent::Complete(s)) => assert_eq!(s, b"A: 1\n"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn remaining_capacity_shrinks_with_the_counted_bytes() {
        let mut h = HeaderCollector::new(20);
        assert_eq!(h.remaining_capacity(), Some(20));
        h.push_line(b"A: 1\r\n");
        assert_eq!(h.remaining_capacity(), Some(14));
        // Dot stuffing is undone first, so "..x\r\n" costs the 4 bytes of
        // ".x\r\n".
        h.push_line(b"..x\r\n");
        assert_eq!(h.remaining_capacity(), Some(10));
    }

    #[test]
    fn mark_too_large_discards_the_block_and_leaves_no_capacity() {
        let mut h = HeaderCollector::new(1000);
        h.push_line(b"A: 1\r\n");
        h.mark_too_large();
        // No capacity is left to report once the collector is discarding.
        assert_eq!(h.remaining_capacity(), None);
        // And what was collected is gone rather than waiting to be handed on.
        assert!(h.take_pending().is_none());
    }

    #[test]
    fn a_body_line_passes_through_unchanged() {
        let mut f = BodyFramer::new();
        assert!(!matches!(f.push(b"hello\r\n"), BodyPiece::Terminator));
        assert_eq!(f.flush(), b"hello\r\n");
    }

    /// Dot stuffing is the client's and the upstream's business. Unstuffing
    /// and restuffing was the identity for correct input, and for a client
    /// that under-stuffed both paths land on the same bytes at the far end.
    #[test]
    fn a_stuffed_line_is_not_touched() {
        let mut f = BodyFramer::new();
        f.push(b"..hidden\r\n");
        assert_eq!(f.flush(), b"..hidden\r\n");
    }

    #[test]
    fn a_bare_newline_becomes_crlf() {
        let mut f = BodyFramer::new();
        f.push(b"hello\n");
        assert_eq!(f.flush(), b"hello\r\n");
    }

    /// A bare CR inside a body line is data, not a line ending: SMTP frames
    /// on LF, so `x\r.\r\n` is a single line and nothing in it is the
    /// terminator. Normalising that CR to CRLF would split the line in two
    /// and hand the upstream a `.\r\n` of its own -- it would end the
    /// message there and read the rest of the body as SMTP commands.
    #[test]
    fn a_bare_cr_in_a_body_line_does_not_manufacture_a_line_start() {
        let mut f = BodyFramer::new();
        assert!(!matches!(f.push(b"x\r.\r\n"), BodyPiece::Terminator));
        assert_eq!(f.flush(), b"x\r.\r\n");
    }

    #[test]
    fn the_terminator_is_recognised_in_both_spellings() {
        assert!(matches!(
            BodyFramer::new().push(b".\r\n"),
            BodyPiece::Terminator
        ));
        assert!(matches!(
            BodyFramer::new().push(b".\n"),
            BodyPiece::Terminator
        ));
    }

    /// Nothing goes out before the staging buffer is full, so a short piece
    /// leaves the framer with something to flush -- and mid-line, which is
    /// what decides whether the next dot ends the message.
    #[test]
    fn a_partial_line_stays_mid_line_and_does_not_end_the_message() {
        let mut f = BodyFramer::new();
        assert!(matches!(
            f.push_partial(b"no break here"),
            BodyPiece::Pending
        ));
        // Still mid-line, so a following "." is body, not a terminator.
        assert!(matches!(f.push(b".\r\n"), BodyPiece::Pending));
        assert_eq!(f.flush(), b"no break here.\r\n");
    }

    /// The buffer is emitted when it fills, line break or not: a client may
    /// send gigabytes without one, and nothing may accumulate while it does.
    #[test]
    fn a_full_buffer_is_emitted_without_a_line_break() {
        let mut f = BodyFramer::new();
        match f.push_partial(&vec![b'x'; WRITE_CHUNK]) {
            BodyPiece::Chunk(c) => assert_eq!(c.len(), WRITE_CHUNK),
            other => panic!("{other:?}"),
        }
        assert!(f.flush().is_empty());
    }

    /// A chunk that ends on a lone CR cannot be normalised yet: the byte is
    /// held back rather than guessed at.
    #[test]
    fn a_trailing_cr_is_carried_to_the_next_piece() {
        let mut f = BodyFramer::new();
        f.push_partial(b"abc\r");
        assert_eq!(f.flush(), b"abc");
        f.push_partial(b"\ndef");
        assert_eq!(f.flush(), b"\r\ndef");
    }

    /// The case that pins the held CR to the framer rather than to the
    /// piece: with an LF after it both a kept and a dropped CR would end up
    /// writing CRLF, so only a continuation that does *not* start with LF
    /// tells the two apart.
    #[test]
    fn a_held_cr_survives_a_flush_with_no_lf_after_it() {
        let mut f = BodyFramer::new();
        f.push_partial(b"abc\r");
        assert_eq!(f.flush(), b"abc");
        f.push_partial(b"def");
        assert_eq!(f.flush(), b"\rdef");
    }

    /// A held CR can never be stranded by the terminator: holding one takes
    /// a partial line, which leaves the framer mid-line, and the terminator
    /// is only ever reported at a line start.
    #[test]
    fn a_held_cr_cannot_be_stranded_by_the_terminator() {
        let mut f = BodyFramer::new();
        f.push_partial(b"abc\r");
        assert!(matches!(f.push(b".\r\n"), BodyPiece::Pending));
        // The held CR is emitted as the data it is, so the dot after it does
        // not begin a line of its own: see
        // `a_bare_cr_in_a_body_line_does_not_manufacture_a_line_start`.
        assert_eq!(f.flush(), b"abc\r.\r\n");
    }
}
