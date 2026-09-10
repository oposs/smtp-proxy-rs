//! Mojo::Log compatible output on top of tracing:
//! `[YYYY-MM-DD HH:MM:SS.fffff] [pid] [level] [cid] message`.
use std::fmt;
use std::path::Path;

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

pub struct MojoFormat;

pub fn format_timestamp(now: &jiff::Zoned) -> String {
    format!(
        "{} {:02}:{:02}:{:02}.{:05}",
        now.date(),
        now.hour(),
        now.minute(),
        now.second(),
        now.subsec_nanosecond() / 10_000
    )
}

fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::DEBUG => "debug",
        Level::INFO => "info",
        Level::WARN => "warn",
        Level::ERROR => "error",
        Level::TRACE => unreachable!("trace events are filtered out by init"),
    }
}

impl<S, N> FormatEvent<S, N> for MojoFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut w: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        write!(
            w,
            "[{}] [{}] [{}] ",
            format_timestamp(&jiff::Zoned::now()),
            std::process::id(),
            level_name(event.metadata().level())
        )?;
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let ext = span.extensions();
                if let Some(fields) = ext.get::<FormattedFields<N>>() {
                    // The default field formatter renders `cid=abc`; only the id is wanted.
                    for field in fields.fields.split(' ') {
                        if let Some(id) = field.strip_prefix("cid=") {
                            write!(w, "[{id}] ")?;
                        }
                    }
                }
            }
        }
        ctx.field_format().format_fields(w.by_ref(), event)?;
        writeln!(w)
    }
}

/// Installs the global subscriber. `level` follows the Perl names; `fatal`
/// silences everything because nothing is ever logged at that level.
pub fn init(path: Option<&Path>, level: &str) -> anyhow::Result<()> {
    let filter = match level {
        "debug" => tracing::level_filters::LevelFilter::DEBUG,
        "info" => tracing::level_filters::LevelFilter::INFO,
        "warn" => tracing::level_filters::LevelFilter::WARN,
        "error" => tracing::level_filters::LevelFilter::ERROR,
        "fatal" => tracing::level_filters::LevelFilter::OFF,
        other => anyhow::bail!("unknown log level '{other}'"),
    };
    let layer = tracing_subscriber::fmt::layer().event_format(MojoFormat);
    match path {
        Some(p) if p != Path::new("/dev/stderr") => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)?;
            let writer = std::sync::Mutex::new(file);
            tracing_subscriber::registry()
                .with(layer.with_writer(writer).with_filter(filter))
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(layer.with_writer(std::io::stderr).with_filter(filter))
                .init();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_has_five_fractional_digits() {
        let z: jiff::Zoned = "2026-09-10T14:13:51.123456789+02:00[Europe/Zurich]"
            .parse()
            .unwrap();
        assert_eq!(format_timestamp(&z), "2026-09-10 14:13:51.12345");
    }

    #[test]
    fn line_layout_matches_mojo_log() {
        use tracing_subscriber::prelude::*;
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer = {
            let buf = buf.clone();
            move || TestWriter(buf.clone())
        };
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .event_format(MojoFormat)
                .with_writer(writer),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("plain message");
            let span = tracing::info_span!("conn", cid = %"deadbeef");
            let _g = span.enter();
            tracing::warn!("scoped message");
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let mut lines = out.lines();
        let first = lines.next().unwrap();
        let pid = std::process::id();
        assert!(first.starts_with('['), "{first}");
        assert!(
            first.ends_with(&format!("] [{pid}] [info] plain message")),
            "{first}"
        );
        let second = lines.next().unwrap();
        assert!(
            second.ends_with(&format!("] [{pid}] [warn] [deadbeef] scoped message")),
            "{second}"
        );
        // [YYYY-MM-DD HH:MM:SS.fffff]
        assert_eq!(first.find(']'), Some(26), "{first}");
    }

    struct TestWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for TestWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
