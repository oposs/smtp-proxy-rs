package FakeHttpApi;

# The conformance counterpart of the Perl suite's FakeAPI. FakeAPI is handed to
# the in-process proxy as an object and its `check` method is called directly,
# so nothing it returns is ever serialised. The binary can only be reached over
# HTTP, so this serves the same canned answers from a real HTTP endpoint on an
# ephemeral port and records the decoded request bodies in `calledWith`.
#
# The accessors are named as FakeAPI names them, so that an adapted test's
# assertions can be copied across unchanged.

use Mojo::Base -base, -signatures;
use Mojolicious;
use Mojo::Server::Daemon;
use Mojo::IOLoop::Server;

has result => sub { { allow => 1, headers => [] } };
has calledWith => sub { [] };
has 'url';

# `allow` is a JSON boolean on the wire (manual, API), and the
# Rust proxy decodes it as one. FakeAPI never went through JSON at all, so its
# tests spell the field as the Perl truth values 1 and 0; they are translated
# here rather than in every test.
sub _encodable ($self) {
    my %out = %{$self->result};
    $out{allow} = $out{allow} ? \1 : \0 if exists $out{allow};
    return \%out;
}

sub start ($self) {
    my $app = Mojolicious->new;
    $app->log->level('error');
    my $me = $self;
    $app->routes->post('/check' => sub ($c) {
        push @{$me->calledWith}, $c->req->json;
        $c->render(json => $me->_encodable);
    });
    my $port = Mojo::IOLoop::Server->generate_port;
    $self->{daemon} = Mojo::Server::Daemon->new(
        app    => $app,
        listen => ["http://127.0.0.1:$port"],
        silent => 1,
    )->start;
    $self->url("http://127.0.0.1:$port/check");
    return $self;
}

sub clear ($self) { @{$self->calledWith} = (); return }

1;
