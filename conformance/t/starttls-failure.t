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
use RecordingSMTPServer;
use Test::More;

# Adapted from the Perl suite's t/starttls-failure.t.
#
# A TLS negotiation that fails is not an exotic case: any client that says
# STARTTLS and then does not speak TLS reaches it, unauthenticated and at will.
# In the Perl the error handler closed the stream and then went on reading from
# $self, which was weakened by then, so the next statement ran on undef and
# took the reactor's I/O watcher down with it.
#
# The original drives SMTPProxy::SMTPServer directly and reads Perl's own
# $SIG{__WARN__} stream for that undef access. A separate binary has no such
# stream, so the middle assertion instead reads the proxy's own log for a
# panic. The other two are the original's, unchanged: the point of the handler
# is to answer 220 and then shut that one connection down without costing the
# listener. See conformance/README.md.

plan tests => 3;

my $TEST_HOST = '127.0.0.1';

my $upstream = RecordingSMTPServer->new(
    port => Mojo::IOLoop::Server->generate_port,
);
$upstream->start;

my $api = FakeHttpApi->new->start;
$api->result({ allow => 1, headers => [] });

my $proxy = ProxyUnderTest->new(
    tohost => $TEST_HOST,
    toport => $upstream->port,
    api    => $api->url,
)->start;
my $TEST_PORT = $proxy->port;

my $goAhead;
my $client = RawSMTPClient->new(address => $TEST_HOST, port => $TEST_PORT);
$client->connect_p
    ->then(sub { $client->command_p('EHLO client.example.com') })
    ->then(sub { $client->command_p('STARTTLS') })
    ->then(sub ($r) {
        $goAhead = $r;
        # Anything that is not a TLS ClientHello will do.
        $client->writeOnly("this is not a TLS handshake\r\n");
        Mojo::IOLoop->timer(1 => sub { Mojo::IOLoop->stop });
        return;
    })
    ->catch(sub ($err) { fail "Session failed: $err"; Mojo::IOLoop->stop });
Mojo::IOLoop->start;

like $goAhead, qr/^220 /, 'STARTTLS is answered before the handshake';
unlike $proxy->log, qr/panicked/,
    'A failed TLS negotiation raises no exception in the proxy';

# The point of the handler is still to shut the connection down.
my $second = RawSMTPClient->new(address => $TEST_HOST, port => $TEST_PORT);
my $stillServing;
$second->connect_p
    ->then(sub ($greeting) { $stillServing = $greeting; $second->close; return })
    ->catch(sub ($err) { fail "Server stopped accepting: $err" })
    ->finally(sub { Mojo::IOLoop->stop });
Mojo::IOLoop->start;
like $stillServing, qr/^220 /, 'The server still accepts new connections';
