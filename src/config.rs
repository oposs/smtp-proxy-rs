//! Command line, with the Perl flag names.
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{CommandFactory, Parser};

use crate::relay::UpstreamTlsMode;

const LONG_ABOUT: &str = "Starts an SMTP server on the listen host and port. When a connection is \
established, communicates with the client up to the point it has both the envelope and the mail \
data headers. It requires STARTTLS to be used, and takes authentication details using the PLAIN \
mechanism. It then passes the authentication details, envelope headers, and data headers to a \
REST API, which determines if the mail is allowed to be sent and, if so, what additional headers \
should be inserted. Once the mail has been fully received, and if it is allowed to be sent, then \
an upstream connection to the target SMTP server is established. The mail is sent using that SMTP \
server, with the extra headers inserted. The outcome of this is then relayed to the client.";

/// The flags of spec section 7, spelled as the Perl proxy spells them. The
/// mandatory ones are `Option` so that `--help` works without them;
/// [`parse_args`] enforces their presence.
#[derive(clap::Parser, Debug, Clone)]
#[command(
    name = "smtp-proxy",
    version,
    about = "SMTP authentication and header injection proxy",
    long_about = LONG_ABOUT,
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct Cli {
    #[arg(long, action = clap::ArgAction::Help, help = "show the full manual and exit")]
    pub man: (),
    #[arg(short = 'h', long, action = clap::ArgAction::HelpShort, help = "show usage and exit")]
    pub help: (),
    #[arg(long, action = clap::ArgAction::Version, help = "print the version and exit")]
    pub version: (),
    #[arg(
        long,
        value_name = "ip:port",
        help = "on which IP should we listen; use 0.0.0.0 to listen on all"
    )]
    pub listen: Vec<String>,
    #[arg(long, help = "drop privileges and become this user after start")]
    pub user: Option<String>,
    #[arg(long, help = "host of the SMTP server to proxy to")]
    pub tohost: Option<String>,
    #[arg(long, help = "port of the SMTP server to proxy to")]
    pub toport: Option<u16>,
    #[arg(
        long = "tls_cert",
        help = "file containing a TLS certificate (for STARTTLS)"
    )]
    pub tls_cert: Option<PathBuf>,
    #[arg(long = "tls_key", help = "file containing a TLS key (for STARTTLS)")]
    pub tls_key: Option<PathBuf>,
    #[arg(long, help = "URL of the authentication API")]
    pub api: Option<String>,
    #[arg(
        long,
        default_value = "/dev/stderr",
        help = "where should the logfile be written to"
    )]
    pub logpath: Option<PathBuf>,
    #[arg(long, default_value = "debug", help = "debug|info|warn|error|fatal")]
    pub loglevel: String,
    #[arg(
        long,
        help = "optional detailed log file of SMTP commands and responses"
    )]
    pub smtplog: Option<PathBuf>,
    #[arg(long, help = "include username and password info in the smtplog")]
    pub credentials: bool,
    #[arg(
        long = "max_header_size",
        default_value_t = 1 << 20,
        help = "largest header block accepted, in bytes; must be at least 1, because the header \
                block is held in memory -- unlike the limits below, 0 does not mean unlimited \
                and is refused at startup"
    )]
    pub max_header_size: usize,
    #[arg(
        long = "upstream_tls",
        value_enum,
        default_value_t = UpstreamTlsMode::Opportunistic,
        help = "TLS on the connection to the upstream: off, opportunistic (STARTTLS when \
                offered), required (STARTTLS always), implicit (TLS from the first byte)"
    )]
    pub upstream_tls: UpstreamTlsMode,
    #[arg(
        long = "upstream_tls_ca",
        help = "additional CA certificates (PEM) to trust for the upstream, on top of the \
                system store"
    )]
    pub upstream_tls_ca: Option<PathBuf>,
    #[arg(
        long = "upstream_tls_insecure",
        help = "do not verify the upstream certificate at all"
    )]
    pub upstream_tls_insecure: bool,
    #[arg(
        long = "max_connections",
        default_value_t = 1000,
        help = "total concurrent connections allowed; 0 means unlimited"
    )]
    pub max_connections: usize,
    #[arg(
        long = "max_connections_per_ip",
        default_value_t = 50,
        help = "concurrent connections allowed from a single client IP, counted per IPv6 /64; 0 means unlimited"
    )]
    pub max_connections_per_ip: usize,
    #[arg(
        long = "max_messages_per_minute",
        default_value_t = 60,
        help = "messages a single authenticated username may start per minute; 0 means unlimited"
    )]
    pub max_messages_per_minute: u32,
    #[arg(
        long = "max_recipients",
        default_value_t = 1000,
        help = "recipients allowed in one message; 0 means unlimited"
    )]
    pub max_recipients: usize,
    #[arg(
        long = "drain_timeout",
        default_value_t = 30,
        help = "seconds to let messages already in flight finish after a shutdown signal; \
                0 means wait as long as they take, and a second signal exits at once either way"
    )]
    pub drain_timeout: u64,
    #[arg(
        long = "greeting_timeout",
        default_value_t = 30,
        help = "seconds a connection may stay silent before it has sent its first command; \
                0 means the ordinary ten-minute inactivity timeout governs that wait too"
    )]
    pub greeting_timeout: u64,
}

/// The command line after the mandatory flags have been checked and the
/// listen addresses parsed.
pub struct Config {
    pub listen: Vec<SocketAddr>,
    pub user: Option<String>,
    pub tohost: String,
    pub toport: u16,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub api: String,
    pub logpath: Option<PathBuf>,
    pub loglevel: String,
    pub smtplog: Option<PathBuf>,
    pub credentials: bool,
    pub max_header_size: usize,
    pub upstream_tls: UpstreamTlsMode,
    pub upstream_tls_ca: Option<PathBuf>,
    pub upstream_tls_insecure: bool,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub max_messages_per_minute: u32,
    pub max_recipients: usize,
    pub drain_timeout: u64,
    pub greeting_timeout: u64,
}

/// `ip:port`, where the ip may be IPv4 or IPv6 and the port is the text
/// after the last colon (spec 7). `[::1]:25` and `::1:25` both work.
pub fn parse_listen(s: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Could not parse {s}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("Could not parse {s}"))?;
    let ip: std::net::IpAddr = host
        .trim_matches(['[', ']'])
        .parse()
        .map_err(|_| anyhow::anyhow!("Could not parse {s}"))?;
    Ok(SocketAddr::new(ip, port))
}

/// What an operator is told when they ask for a header cap of zero bytes.
const MAX_HEADER_SIZE_ZERO: &str = "--max_header_size must be at least 1: unlike the other \
limits, 0 does not mean unlimited here, because the header block is held in memory";

/// Limit values that parse but cannot be honoured. Separate from
/// [`parse_args`] so that it can be tested without exiting the process.
///
/// `--max_connections`, `--max_connections_per_ip`, `--max_messages_per_minute`
/// and `--max_recipients` all read 0 as "unlimited", and `--max_header_size`
/// looks like one more of that family. It is not: the header block is the
/// one part of a message this proxy holds in memory -- the body is streamed
/// to the upstream precisely so that nothing unbounded is held -- so there is
/// no unlimited setting to offer. Taken literally, 0 is a cap the first
/// header line of every message exceeds, which is why this is a startup
/// error rather than a silent reinterpretation either way.
fn check_limits(cli: &Cli) -> Result<(), String> {
    if cli.max_header_size == 0 {
        return Err(MAX_HEADER_SIZE_ZERO.to_string());
    }
    Ok(())
}

/// What `pod2usage` does for a bad command line: the complaint, the usage,
/// and exit status 1. Only for the checks this module makes by hand -- a
/// clap error already renders its own usage, and passing one through here
/// would print a second, differently worded one.
fn usage_exit(message: &str) -> ! {
    eprintln!("{message}");
    eprintln!("{}", Cli::command().render_usage());
    eprintln!("Try '--help' for more information.");
    std::process::exit(1)
}

/// Parses argv. Help and version exit 0. A usage error (missing mandatory
/// flag, unparseable value) prints the usage to stderr and exits 1, as
/// pod2usage does.
pub fn parse_args() -> Config {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        // clap's own rendering is already the complaint, a `Usage:` block
        // and a hint, and it ends in a newline -- `eprint!`, so that it is
        // not followed by a blank line and a second usage block.
        Err(e) if e.use_stderr() => {
            eprint!("{e}");
            std::process::exit(1)
        }
        Err(e) => e.exit(), // --help, --man, --version
    };
    if let Err(complaint) = check_limits(&cli) {
        usage_exit(&complaint)
    }
    let listen = if cli.listen.is_empty() {
        usage_exit("--listen is required")
    } else {
        cli.listen
            .iter()
            .map(|s| parse_listen(s))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| usage_exit(&e.to_string()))
    };
    // `stringify!(tls_cert)` yields the flag spelling, so the message reads
    // `--tls_cert is required`.
    macro_rules! required {
        ($field:ident) => {
            cli.$field
                .clone()
                .unwrap_or_else(|| usage_exit(concat!("--", stringify!($field), " is required")))
        };
    }
    Config {
        listen,
        user: cli.user.clone(),
        tohost: required!(tohost),
        toport: required!(toport),
        tls_cert: required!(tls_cert),
        tls_key: required!(tls_key),
        api: required!(api),
        logpath: cli.logpath.clone(),
        loglevel: cli.loglevel.clone(),
        smtplog: cli.smtplog.clone(),
        credentials: cli.credentials,
        max_header_size: cli.max_header_size,
        upstream_tls: cli.upstream_tls,
        upstream_tls_ca: cli.upstream_tls_ca.clone(),
        upstream_tls_insecure: cli.upstream_tls_insecure,
        max_connections: cli.max_connections,
        max_connections_per_ip: cli.max_connections_per_ip,
        max_messages_per_minute: cli.max_messages_per_minute,
        max_recipients: cli.max_recipients,
        drain_timeout: cli.drain_timeout,
        greeting_timeout: cli.greeting_timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_forms() {
        assert_eq!(
            parse_listen("127.0.0.1:2525").unwrap(),
            "127.0.0.1:2525".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen("0.0.0.0:25").unwrap(),
            "0.0.0.0:25".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen("::1:25").unwrap(),
            "[::1]:25".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen("[::1]:25").unwrap(),
            "[::1]:25".parse::<SocketAddr>().unwrap()
        );
        assert!(parse_listen("nonsense").is_err());
        assert!(parse_listen("127.0.0.1:notaport").is_err());
    }

    /// Every other `--max_*` flag reads 0 as "unlimited". An operator who
    /// carries that convention across to `--max_header_size` used to get the
    /// exact opposite of what they asked for: a cap of zero bytes, which the
    /// first header line of every message exceeds, so every message with any
    /// header at all died with 552. Unlimited is not on offer for this one,
    /// so the only honest answer is to refuse the value at startup.
    #[test]
    fn max_header_size_zero_is_a_configuration_error() {
        let cli = Cli::try_parse_from(["smtp-proxy", "--max_header_size", "0"]).unwrap();
        let complaint = check_limits(&cli).expect_err("--max_header_size 0 must be refused");
        assert!(
            complaint.starts_with("--max_header_size "),
            "the complaint must name the flag: {complaint}"
        );
        assert!(
            complaint.contains("unlimited"),
            "the complaint must say that 0 is not unlimited: {complaint}"
        );
    }

    /// The guard must not fire on the default, nor on the smallest value it
    /// does accept.
    #[test]
    fn max_header_size_above_zero_is_accepted() {
        for value in ["1", "1048576"] {
            let cli = Cli::try_parse_from(["smtp-proxy", "--max_header_size", value]).unwrap();
            assert!(check_limits(&cli).is_ok(), "--max_header_size {value}");
        }
        let cli = Cli::try_parse_from(["smtp-proxy"]).unwrap();
        assert!(check_limits(&cli).is_ok(), "the default");
    }
}
