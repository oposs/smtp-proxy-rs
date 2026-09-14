use FindBin;
use lib "$FindBin::Bin/../lib";
use ConformancePaths;
use strict;
use warnings;
use v5.16;

use FakeHttpApi;
use ProxyUnderTest;
use Mojo::Promise;
use Mojo::SMTP::Client;
use SMTPProxy::SMTPServer;
use Test::More;

# Adapted from the Perl suite's t/end-to-end.t. Every assertion is the
# original's. What changed is the proxy in the middle: the in-process
# SMTPProxy object is replaced by the compiled Rust binary on a real socket,
# and the in-process FakeAPI by an HTTP endpoint the binary can call.
#
# The upstream is still the Perl SMTPProxy::SMTPServer, because the assertions
# are about what reached it -- envelope, headers and body -- and reading those
# out of its callbacks is exactly what the original does.

plan tests => 34;

# Test infrastructure

my $TEST_HOST = '127.0.0.1';
my $TEST_TO_PORT = Mojo::IOLoop::Server->generate_port;
my $TEST_LOG = Mojo::Log->new(level => $ENV{TEST_LOG_LEVEL} // 'fatal');

# Assigned once the binary has reported the port the kernel gave it. Declared
# here so the test-case subs below close over the same variable.
my $TEST_PROXY_PORT;

my $testApi = FakeHttpApi->new->start;
my %toSMTPServerSent;
my $fakeServerError;
sub setupTestSMTPTarget {
    my $server = SMTPProxy::SMTPServer->new(
        log => $TEST_LOG,
        listen => [$TEST_HOST.':'.$TEST_TO_PORT],
        service_name => 'test.to.service',
        require_starttls => 0,
        require_auth => 0,
    );
    $server->setup(sub {
        my $connection = shift;
        $connection->auth(sub {
            my ($authzid, $authcid, $password) = @_;
            fail "Target SMTP server should not be auth'd";
            return Mojo::Promise->reject;
        });
        $connection->mail(sub {
            my ($from, $parameters) = @_;
            $toSMTPServerSent{from} = $from;
            return $fakeServerError
                ? Mojo::Promise->new->reject($fakeServerError)
                : Mojo::Promise->new->resolve;
        });
        $connection->rcpt(sub {
            my ($to, $parameters) = @_;
            $toSMTPServerSent{to} //= [];
            push @{$toSMTPServerSent{to}}, $to;
            return Mojo::Promise->new->resolve;
        });
        $connection->data(sub {
            my ($headersPromise, $bodyPromise) = @_;
            my $result = Mojo::Promise->new;
            $headersPromise->then(sub {
                $toSMTPServerSent{headers} = shift;
            });
            $bodyPromise->then(sub {
                $toSMTPServerSent{body} = shift;
                $result->resolve;
            });
        });
        $connection->vrfy(sub {
            return Mojo::Promise->new->reject(553, 'User ambiguous');
        });
    });
}

sub runTestCases {
    my @testCases = @_;
    Mojo::IOLoop->next_tick(sub {
        runOneTestCase(@testCases);
    });
    Mojo::IOLoop->start;
}

sub runOneTestCase {
    my ($test, @rest) = @_;
    %toSMTPServerSent = ();
    $testApi->clear();
    $fakeServerError = '';
    $test->(@rest
        ? sub { runOneTestCase(@rest) }
        : sub { Mojo::IOLoop->stop });
}

# The upstream binds as soon as it is set up, so it is listening before the
# proxy is started and the proxy's startup probe finds someone home.
setupTestSMTPTarget();
my $proxy = ProxyUnderTest->new(
    tohost => $TEST_HOST,
    toport => $TEST_TO_PORT,
    api    => $testApi->url,
)->start;
$TEST_PROXY_PORT = $proxy->port;

# Tests

runTestCases(\&allowedSimple, \&denied, \&allowedInsertHeaders, \&relayError,
    \&transparency, \&allowedChangeFrom, \&allowedChangeHeaders, \&loginAuth,\&multiMail);

sub allowedSimple {
    my $done = shift;

    $testApi->result({
        allow => 1,
        headers => []
    });

    my $smtp = Mojo::SMTP::Client->new(
        address => $TEST_HOST,
        port => $TEST_PROXY_PORT,
        autodie => 1,
        tls_verify => 0,
    );
    $smtp->send(
        starttls => 1,
        auth     => {login => 'fooser', password => 's3cr3t'},
        from     => 'sender@foobar.com',
        to       => ['another@foobaz.com', 'brother@foobaz.com'],
        data     => join("\r\n",
                        'Subject: Some message subject',
                        'From: from@foobar.com',
                        'To: another@foobaz.com',
                        'Cc: brother@foobaz.com',
                        '',
                        'Some message text',
                        'More message text'),
        quit     => 1,
        sub {
            my ($smtp, $resp) = @_;
            ok(!($resp->error), 'Allowed mail accepted by proxy');

            is $toSMTPServerSent{from}, 'sender@foobar.com',
                'Envelope from correctly relayed';
            is_deeply $toSMTPServerSent{to},
                ['another@foobaz.com', 'brother@foobaz.com'],
                'Envelope recipients correctly relayed';
            my $expectedHeaders = join "\r\n",
                'Subject: Some message subject',
                'From: from@foobar.com',
                'To: another@foobaz.com',
                'Cc: brother@foobaz.com',
                '';
            is $toSMTPServerSent{headers}, $expectedHeaders,
                'Headers correctly relayed';
            my $expectedBody = join "\r\n",
                'Some message text',
                'More message text',
                '';
            is $toSMTPServerSent{body}, $expectedBody,
                'Body correctly relayed';

            my @calls = @{$testApi->calledWith};
            is scalar(@calls), 1, 'Made a single call to the API';
            is $calls[0]->{username}, 'fooser', 'Correct username sent to API';
            is $calls[0]->{password}, 's3cr3t', 'Correct password sent to API';
            is $calls[0]->{from}, 'sender@foobar.com', 'Correct to sent to API';
            is_deeply $calls[0]->{to},
                ['another@foobaz.com', 'brother@foobaz.com'],
                'Correct to sent to API';
            is_deeply $calls[0]->{headers},
                [
                    { name => 'Subject', value => 'Some message subject' },
                    { name => 'From', value => 'from@foobar.com' },
                    { name => 'To', value => 'another@foobaz.com' },
                    { name => 'Cc', value => 'brother@foobaz.com' },
                ],
                'Correct headers sent to API';

            $done->();
        }
    );
}

sub denied {
    my $done = shift;

    $testApi->result({
        allow => 0,
        reason => 'bad username or password'
    });

    my $smtp = Mojo::SMTP::Client->new(
        address => $TEST_HOST,
        port => $TEST_PROXY_PORT,
        autodie => 1,
        tls_verify => 0,
    );
    $smtp->send(
        starttls => 1,
        auth     => {login => 'fuser', password => 's3cr3t'},
        from     => 'sender@foobar.com',
        to       => 'another@foobaz.com',
        data     => join("\r\n",
                        'Subject: Some message subject',
                        'From: from@foobar.com',
                        'To: another@foobaz.com',
                        '',
                        'Some message text',
                        'More message text'),
        quit     => 1,
        sub {
            my ($smtp, $resp) = @_;
            ok($resp->error, 'Mail not accepted by proxy');
            like $resp->error, qr/bad username or password/,
                'Error text returned from API is sent onwards';
            ok !defined($toSMTPServerSent{from}), 'Did not relay mail';
            $done->();
        }
    );
}

sub allowedInsertHeaders {
    my $done = shift;

    $testApi->result({
        allow => 1,
        headers => [
            { name => 'Sender', value => 'sender@foobar.com' },
            { name => 'X-Parrot', value => 'Norwegian blue' },
        ]
    });

    my $smtp = Mojo::SMTP::Client->new(
        address => $TEST_HOST,
        port => $TEST_PROXY_PORT,
        autodie => 1,
        tls_verify => 0,
    );
    $smtp->send(
        starttls => 1,
        auth     => {login => 'fooser', password => 's3cr3t'},
        from     => 'sender@foobar.com',
        to       => ['another@foobaz.com'],
        data     => join("\r\n",
                        'Subject: Some message subject',
                        'From: from@foobar.com',
                        'To: another@foobaz.com',
                        '',
                        'Some message text',
                        'More message text'),
        quit     => 1,
        sub {
            my ($smtp, $resp) = @_;
            ok(!($resp->error), 'Allowed mail accepted by proxy');
            my $expectedHeaders = join "\r\n",
                'Subject: Some message subject',
                'From: from@foobar.com',
                'To: another@foobaz.com',
                'Sender: sender@foobar.com',
                'X-Parrot: Norwegian blue',
                '';
            is $toSMTPServerSent{headers}, $expectedHeaders,
                'Headers relayed include those added by the API';
            $done->();
        }
    );
}

sub relayError {
    my $done = shift;

    $testApi->result({
        allow => 1,
        headers => []
    });
    $fakeServerError = "Sorry, I don't send from there";

    my $smtp = Mojo::SMTP::Client->new(
        address => $TEST_HOST,
        port => $TEST_PROXY_PORT,
        autodie => 1,
        tls_verify => 0,
    );
    $smtp->send(
        starttls => 1,
        auth     => {login => 'fooser', password => 's3cr3t'},
        from     => 'sender@foobar.com',
        to       => ['another@foobaz.com', 'brother@foobaz.com'],
        data     => join("\r\n",
                        'Subject: Some message subject',
                        'From: from@foobar.com',
                        'To: another@foobaz.com',
                        'Cc: brother@foobaz.com',
                        '',
                        'Some message text',
                        'More message text'),
        quit     => 1,
        sub {
            my ($smtp, $resp) = @_;
            ok($resp->error, 'Mail did not send due to relay server rejection');
            is $toSMTPServerSent{from}, 'sender@foobar.com',
                'Really did try to call relay server';
            like $resp->error, qr/Sorry, I don't send from there/,
                'Error text returned from relay server is sent onwards';
            $done->();
        }
    );
}

sub transparency {
    my $done = shift;

    $testApi->result({
        allow => 1,
        headers => []
    });

    my $smtp = Mojo::SMTP::Client->new(
        address => $TEST_HOST,
        port => $TEST_PROXY_PORT,
        autodie => 1,
        tls_verify => 0,
    );
    $smtp->send(
        starttls => 1,
        auth     => {login => 'fooser', password => 's3cr3t'},
        from     => 'sender@foobar.com',
        to       => ['another@foobaz.com'],
        data     => join("\r\n",
                        'Subject: Some message subject',
                        'From: from@foobar.com',
                        'To: another@foobaz.com',
                        '',
                        'Some message text before . line',
                        '.',
                        'More message text after . line'),
        quit     => 1,
        sub {
            my ($smtp, $resp) = @_;
            ok(!($resp->error), 'Mail with lone . line in body accepted by proxy');
            my $expectedBody = join "\r\n",
                'Some message text before . line',
                '.',
                'More message text after . line',
                '';
            is $toSMTPServerSent{body}, $expectedBody,
                'Body with a line . line correctly relayed';
            $done->();
        }
    );
}

sub allowedChangeFrom {
    my $done = shift;

    $testApi->result({
        allow => 1,
        headers => [],
        from => 'different@foobar.com'
    });

    my $smtp = Mojo::SMTP::Client->new(
        address => $TEST_HOST,
        port => $TEST_PROXY_PORT,
        autodie => 1,
        tls_verify => 0,
    );
    $smtp->send(
        starttls => 1,
        auth     => {login => 'fooser', password => 's3cr3t'},
        from     => 'sender@foobar.com',
        to       => ['another@foobaz.com'],
        data     => join("\r\n",
                        'Subject: Some message subject',
                        'From: from@foobar.com',
                        'To: another@foobaz.com',
                        '',
                        'Some message text',
                        'More message text'),
        quit     => 1,
        sub {
            my ($smtp, $resp) = @_;
            ok(!($resp->error), 'Allowed mail accepted by proxy');
            is $toSMTPServerSent{from}, 'different@foobar.com',
                'Mail used the replacement `from` returned by the API';
            my $expectedHeaders = join "\r\n",
                'Subject: Some message subject',
                'From: from@foobar.com',
                'To: another@foobaz.com',
                '';
            is $toSMTPServerSent{headers}, $expectedHeaders,
                'Headers left as is, as not returned by the API';
            $done->();
        }
    );
}

sub allowedChangeHeaders {
    my $done = shift;

    $testApi->result({
        allow => 1,
        headers => [
            { name => 'X-GoAway', value => undef },
            { name => 'X-ReplaceMe', value => 'a new header' },
            { name => 'X-ReplaceMe', value => 'another new header' },
        ]
    });

    my $smtp = Mojo::SMTP::Client->new(
        address => $TEST_HOST,
        port => $TEST_PROXY_PORT,
        autodie => 1,
        tls_verify => 0,
    );
    $smtp->send(
        starttls => 1,
        auth     => {login => 'fooser', password => 's3cr3t'},
        from     => 'sender@foobar.com',
        to       => ['another@foobaz.com'],
        data     => join("\r\n",
                        'Subject: Some message subject',
                        'X-GoAway: this will be removed',
                        'X-ReplaceMe: this will be replaced',
                        'X-ReplaceMe: this will also be replaced',
                        'From: from@foobar.com',
                        'To: another@foobaz.com',
                        '',
                        'Some message text',
                        'More message text'),
        quit     => 1,
        sub {
            my ($smtp, $resp) = @_;
            ok(!($resp->error), 'Allowed mail accepted by proxy');
            my $expectedHeaders = join "\r\n",
                'Subject: Some message subject',
                'From: from@foobar.com',
                'To: another@foobaz.com',
                'X-ReplaceMe: a new header',
                'X-ReplaceMe: another new header',
                '';
            is $toSMTPServerSent{headers}, $expectedHeaders,
                'Headers removed/replaced as the API requested';
            $done->();
        }
    );
}

sub loginAuth {
    my $done = shift;

    $testApi->result({
        allow => 1,
        headers => []
    });

    my $smtp = Mojo::SMTP::Client->new(
        address => $TEST_HOST,
        port => $TEST_PROXY_PORT,
        autodie => 1,
        tls_verify => 0,
    );
    $smtp->send(
        starttls => 1,
        auth     => {type => 'login', login => 'fooser', password => 's3cr3t'},
        from     => 'sender@foobar.com',
        to       => ['another@foobaz.com', 'brother@foobaz.com'],
        data     => join("\r\n",
                        'Subject: Some message subject',
                        'From: from@foobar.com',
                        'To: another@foobaz.com',
                        '',
                        'Some message text',
                        'More message text'),
        quit     => 1,
        sub {
            my ($smtp, $resp) = @_;
            ok(!($resp->error), 'Allowed mail accepted by proxy using login auth');

            my @calls = @{$testApi->calledWith};
            is scalar(@calls), 1, 'Made a single call to the API';
            is $calls[0]->{username}, 'fooser',
                'Correct username sent to API using login auth';
            is $calls[0]->{password}, 's3cr3t',
                'Correct password sent to API using login auth';

            $done->();
        }
    );
}

sub multiMail {
    my $done = shift;

    $testApi->result({
        allow => 1,
        headers => []
    });

    my $smtp = Mojo::SMTP::Client->new(
        address => $TEST_HOST,
        port => $TEST_PROXY_PORT,
        autodie => 1,
        tls_verify => 0,
    );
    $smtp->send(
        starttls => 1,
        auth     => {type => 'login', login => 'fooser', password => 's3cr3t'},
        from     => 'sender@foobar.com',
        to       => ['r1@foobaz.com'],
        data     => join("\r\n",
                        'Subject: Some message subject',
                        'From: from@foobar.com',
                        'To: another@foobaz.com',
                        '',
                        'Some message text',
                        'More message text'),
        from     => 'sender@foobar.com',
        to       => ['r2@foobaz.com','r3@gugus.li'],
        data     => join("\r\n",
                        'Subject: Other Subject',
                        'From: from@foobar.com',
                        'To: basf@foobaz.com',
                        '',
                        'Some message text',
                        'More message text'),

        quit     => 1,
        sub {
            my ($smtp, $resp) = @_;
            ok(!($resp->error), 'Allowed mail accepted by proxy using login auth');

            my @calls = @{$testApi->calledWith};
            is scalar(@calls), 2, 'Made two calls to the API';
            is_deeply $calls[0]->{to}, ['r1@foobaz.com'],
                'Correct Recipients for first mail';
            is_deeply $calls[1]->{to}, ['r2@foobaz.com','r3@gugus.li'],
                'Correct Recipients for second mail';
            $done->();
        }
    );
}
