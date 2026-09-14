package ProxyUnderTest;

# Runs the compiled Rust proxy as a child process and tells the test which port
# it landed on. This is the whole point of the conformance suite: the Perl tests
# drive a real binary over a real socket instead of an in-process object, so
# anything they observe is what a client on the wire would observe.
#
# The proxy is started with `--listen 127.0.0.1:0` and the port is read back
# from its startup banner, so two test files running at once cannot collide the
# way a pre-generated port can.

use Mojo::Base -base, -signatures;
use ConformancePaths;
use IPC::Open3;
use IO::Select;
use File::Temp qw(tempfile);
use Mojo::File;
use Mojo::IOLoop;
use Mojo::Promise;
use POSIX ();
use Symbol qw(gensym);

has binary => sub { ConformancePaths::binary() };
has certs  => sub { ConformancePaths::certs() };

# Every limit off by default. The Perl has no rate limiting, no recipient cap
# and no connection cap at all, so leaving ours at its production defaults would
# make the gate measure a policy the authority does not have.
has max_connections         => 0;
has max_connections_per_ip  => 0;
has max_messages_per_minute => 0;
has max_recipients          => 0;

has loglevel => 'debug';

has [qw(tohost toport api port pid logpath)];

# Seconds to wait for the startup banner. Generous: the binary may be cold and
# the host shared.
my $STARTUP_TIMEOUT = 30;

sub start ($self) {
    my (undef, $log) = tempfile('smtp-proxy-conformance-XXXXXX', TMPDIR => 1, UNLINK => 1);
    $self->logpath($log);
    my @cmd = (
        $self->binary,
        '--listen',   '127.0.0.1:0',
        '--tohost',   $self->tohost,
        '--toport',   $self->toport,
        '--tls_cert', $self->certs . '/server.crt',
        '--tls_key',  $self->certs . '/server.key',
        '--api',      $self->api,
        '--upstream_tls', 'off',
        '--max_connections',         $self->max_connections,
        '--max_connections_per_ip',  $self->max_connections_per_ip,
        '--max_messages_per_minute', $self->max_messages_per_minute,
        '--max_recipients',          $self->max_recipients,
        '--loglevel', $self->loglevel,
        '--logpath',  $log,
    );
    my $err = gensym;
    my $pid = open3(my $in, my $out, $err, @cmd)
        or die "cannot start @cmd: $!";
    $self->pid($pid);
    $self->{in}  = $in;
    $self->{out} = $out;
    $self->{err} = $err;

    $self->{stdout} = '';
    my $line = $self->_readBannerLine
        // die "the proxy printed no startup banner; stderr: " . $self->_drainStderr;
    $line =~ /Waiting for connections on 127\.0\.0\.1:(\d+)/
        or die "unexpected startup line: $line";
    $self->port($1);
    # Checked, not discarded. A banner that stops after one line means the
    # proxy died between binding and announcing its upstream, and swallowing
    # that spent the whole startup timeout and then carried on to fail later,
    # somewhere less informative.
    my $forward = $self->_readBannerLine
        // die "the proxy announced its port but not its upstream; stderr: "
            . $self->_drainStderr;
    $forward =~ /Will forward mails to /
        or die "unexpected second startup line: $forward";
    return $self;
}

# A blocking readline would hang for good if the proxy died before printing
# anything -- a missing certificate, a port already taken -- and a hung test
# file is much harder to diagnose than a failed one.
#
# Only sysread, never <$out>: readline fills a buffer of its own, and both
# banner lines arrive in a single packet. The second line then sits in that
# buffer while select, which can only see the file descriptor, reports nothing
# to read and blocks until it gives up. That cost a whole timeout per proxy on
# every start, which was long enough to push the proxy's own upstream probe
# past its deadline and make the gate report a DSN failure that was the
# harness's fault.
sub _readBannerLine ($self) {
    my $select = IO::Select->new($self->{out});
    my $deadline = time + $STARTUP_TIMEOUT;
    while (1) {
        if ($self->{stdout} =~ s/^([^\n]*\n)//) {
            return $1;
        }
        my $left = $deadline - time;
        return undef if $left <= 0 || !$select->can_read($left);
        my $chunk;
        my $read = sysread($self->{out}, $chunk, 4096);
        return undef if !defined $read || $read == 0;
        $self->{stdout} .= $chunk;
    }
}

sub _drainStderr ($self) {
    my $select = IO::Select->new($self->{err});
    my $text = '';
    while ($select->can_read(0.2)) {
        my $chunk;
        last unless sysread($self->{err}, $chunk, 4096);
        $text .= $chunk;
    }
    return $text eq '' ? '(nothing on stderr)' : $text;
}

sub log ($self) {
    return Mojo::File->new($self->logpath)->slurp;
}

# Resolves once the proxy's startup probe of the upstream has settled, so that
# what a client is told about DSN does not depend on whether it beat the
# question. The in-process suite awaits `$proxy->upstreamProbe`; a separate
# process has no such handle, so the proxy's own log line is the signal.
#
# Polls on the reactor rather than blocking, because the upstream the probe is
# talking to is served by this very event loop.
sub probeSettled_p ($self) {
    my $promise = Mojo::Promise->new;
    my $deadline = time + 15;
    my $check;
    $check = sub {
        my $log = eval { $self->log } // '';
        if ($log =~ /announces DSN|does not announce DSN|Could not ask/) {
            undef $check;
            return $promise->resolve;
        }
        if (time > $deadline) {
            undef $check;
            return $promise->reject('timed out waiting for the upstream DSN probe');
        }
        Mojo::IOLoop->timer(0.05 => $check);
    };
    $check->();
    return $promise;
}

sub stop ($self) {
    my $pid = $self->pid or return;
    $self->pid(undef);
    kill TERM => $pid;
    # SIGTERM starts a drain, so the exit is not instantaneous even when there
    # is nothing to drain. A test that leaves the process behind would hold the
    # upstream port and break whatever runs next, so the wait is bounded and
    # ends in SIGKILL rather than in giving up.
    for (1 .. 100) {
        # -1 as well as the pid: a test may have reaped the child itself while
        # checking that it was still alive, and waiting five seconds for a
        # child that no longer exists helps nobody.
        my $reaped = waitpid($pid, POSIX::WNOHANG());
        return if $reaped == $pid || $reaped == -1;
        select undef, undef, undef, 0.05;
    }
    kill KILL => $pid;
    waitpid $pid, 0;
    return;
}

sub DESTROY ($self) { $self->stop if $self->pid }

1;
