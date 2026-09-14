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

# Adapted from the Perl suite's t/pipelining.t.
#
# RFC 2920: a client may send a group of commands in one write and read the
# replies afterwards. Everything that has arrived has to be processed, in
# order, one command at a time -- so this exercises three things at once: that
# the reader does not stop after the first command in a packet, that a command
# is not dispatched while the previous one is still deciding, and that the
# message terminator hands back what follows it instead of destroying it.
#
# The original drives SMTPProxy::SMTPServer directly with require_starttls and
# require_auth off, and injects a deliberately slow MAIL callback to prove the
# serialisation. Neither is reachable through a binary that always requires
# STARTTLS and AUTH, so the pipelined groups are sent after the session is
# authenticated, and the one assertion that read the injected callback order is
# dropped. What that assertion was guarding is still measured on the wire: the
# RCPT behind the MAIL is answered 250 and not 503, which is only true if the
# MAIL settled first. See conformance/README.md.

plan tests => 8;

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

# Reads exactly $count replies, however they are packed into TCP segments.
sub expectReplies_p ($client, $count) {
    my @replies;
    my $next;
    $next = sub {
        return Mojo::Promise->resolve(\@replies) unless $count--;
        return $client->expectReply_p->then(sub ($r) { push @replies, $r; $next->() });
    };
    return $next->();
}

my %got;
my $client = RawSMTPClient->new(address => $TEST_HOST, port => $TEST_PORT);
$client->connect_p
    # STARTTLS may not be pipelined (RFC 3207), so the session is brought up to
    # an authenticated state one command at a time before the groups begin.
    ->then(sub { $client->command_p('EHLO client.example.com') })
    ->then(sub { $client->command_p('STARTTLS') })
    ->then(sub { $client->startTLS_p })
    ->then(sub { $client->command_p('EHLO client.example.com') })
    ->then(sub { $client->authPlain_p('fooser', 's3cr3t') })
    ->then(sub {
        # Three commands, one write.
        $client->writeOnly("EHLO client.example.com\r\nNOOP\r\nNOOP\r\n");
        return expectReplies_p($client, 3);
    })
    ->then(sub ($replies) {
        $got{batch} = $replies;
        # A pipelined transaction.
        $client->writeOnly("MAIL FROM:<a\@b.com>\r\nRCPT TO:<c\@d.com>\r\nDATA\r\n");
        return expectReplies_p($client, 3);
    })
    ->then(sub ($replies) {
        $got{transaction} = $replies;
        # The terminating dot and the next command in one write.
        $client->writeOnly("Subject: x\r\n\r\nbody\r\n.\r\nQUIT\r\n");
        return expectReplies_p($client, 2);
    })
    ->then(sub ($replies) { $got{end} = $replies; $client->close; return })
    ->catch(sub ($err) { fail "Session failed: $err" })
    ->finally(sub { Mojo::IOLoop->stop });
Mojo::IOLoop->start;

is scalar(@{$got{batch} // []}), 3, 'Three pipelined commands draw three replies';
like $got{batch}[0], qr/^250[- ]/, 'The EHLO in the group is answered';
is $got{batch}[1], "250 OK\r\n", 'The first NOOP behind it is answered';
is $got{batch}[2], "250 OK\r\n", 'The second NOOP behind it is answered';

like $got{transaction}[0], qr/^250 /, 'MAIL is answered first';
like $got{transaction}[1], qr/^250 /, 'RCPT is answered second, not 503';
like $got{transaction}[2], qr/^354 /, 'DATA is answered third';

like $got{end}[1], qr/^221 /,
    'A QUIT written with the terminating dot is still answered';
