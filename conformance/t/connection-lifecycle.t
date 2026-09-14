use FindBin;
use lib "$FindBin::Bin/../lib";
use ConformancePaths;
use strict;
use warnings;
use Mojo::Base -strict, -signatures;

use FakeHttpApi;
use ProxyUnderTest;
use Mojo::IOLoop;
use Mojo::IOLoop::Server;
use Mojo::Log;
use Mojo::Promise;
use RawSMTPClient;
use Test::More;

plan tests => 4;

# Adapted from the Perl suite's t/connection-lifecycle.t.
#
# A client may hang up while the proxy is still relaying its mail. The session
# is then gone by the time the relay settles, and whatever wanted to reply to
# the client must cope with that instead of taking the process down with it.
#
# Two of the original's four assertions read Perl's own $SIG{__WARN__} stream
# for "Unhandled rejected promise" and "on an undefined value". Those are
# in-process artefacts of the Perl runtime and have no counterpart in a
# separate binary, so each is replaced by the observable consequence it was
# standing in for: a proxy that survived the race is still running and still
# serving. See conformance/README.md.

my $TEST_HOST = '127.0.0.1';
my $UPSTREAM_PORT = Mojo::IOLoop::Server->generate_port;

# Upstream that greets, then drops the connection shortly after the relay
# starts talking to it, so the relay fails after the client has gone.
Mojo::IOLoop->server({address => $TEST_HOST, port => $UPSTREAM_PORT} => sub ($loop, $stream, $id) {
    $stream->write("220 doomed.upstream ready\r\n");
    $stream->on(read => sub ($stream, $bytes) {
        $stream->{closing} //= Mojo::IOLoop->timer(1 => sub { $stream->close });
    });
});

my $api = FakeHttpApi->new->start;
$api->result({ allow => 1, headers => [] });

my $proxy = ProxyUnderTest->new(
    tohost   => $TEST_HOST,
    toport   => $UPSTREAM_PORT,
    api      => $api->url,
    loglevel => 'info',
)->start;
my $PROXY_PORT = $proxy->port;

my $client = RawSMTPClient->new(address => $TEST_HOST, port => $PROXY_PORT);
$client->connect_p
    ->then(sub { $client->command_p('EHLO test.client') })
    ->then(sub { $client->command_p('STARTTLS') })
    ->then(sub { $client->startTLS_p })
    ->then(sub { $client->command_p('EHLO test.client') })
    ->then(sub { $client->authPlain_p('fooser', 's3cr3t') })
    ->then(sub { $client->command_p('MAIL FROM:<sender@foobar.com>') })
    ->then(sub { $client->command_p('RCPT TO:<another@foobaz.com>') })
    ->then(sub { $client->command_p('DATA') })
    ->then(sub {
        $client->writeOnly("Subject: x\r\nFrom: a\@b.com\r\n\r\nbody\r\n.\r\n");
        # Hang up while the proxy is still relaying.
        Mojo::IOLoop->timer(0.3 => sub { $client->close });
        return;
    })
    ->catch(sub ($err) { fail "Client session failed: $err" });

# Long enough for the upstream to drop the relay after the client has gone.
Mojo::IOLoop->timer(4 => sub { Mojo::IOLoop->stop });
Mojo::IOLoop->start;

my $logOutput = $proxy->log;

# Replaces 'No unhandled rejected promise'. A rejection nobody handled is a
# Perl runtime concept; what it cost was the process, so that is what is
# measured here.
is kill(0 => $proxy->pid), 1, 'The proxy process survived the race';

# Replaces 'Nothing called a method on the departed connection'. Same reason:
# the damage such a call did was to stop the proxy serving.
my $stillServing;
my $second = RawSMTPClient->new(address => $TEST_HOST, port => $PROXY_PORT);
$second->connect_p
    ->then(sub ($greeting) { $stillServing = $greeting; $second->close; return })
    ->catch(sub ($err) { fail "Proxy stopped accepting: $err" })
    ->finally(sub { Mojo::IOLoop->stop });
Mojo::IOLoop->start;
like $stillServing, qr/^220 /, 'The proxy still accepts new connections';

# Proves the test actually exercised the race rather than passing vacuously:
# the connection really was gone by the time the relay settled.
#
# The Perl has one place that can notice, so it always logs "left before". The
# proxy has two, and which one fires is decided by TCP rather than by policy:
# the client closed with a FIN, so writing the rejection into the socket still
# succeeds and only the read that follows sees the EOF. Measured on this branch
# the "hung up" line therefore wins every time. Both lines record the same
# fact, at info as spec 4.7 requires, so both satisfy what this assertion is
# for. See conformance/README.md.
like $logOutput, qr/left before|hung up/,
    'Proxy noticed the client had gone before the relay settled';
unlike $logOutput, qr/panicked/,
    'Nothing panicked while the relay settled';
