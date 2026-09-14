package ConformancePaths;

# Resolves the three paths every conformance test needs -- the Rust repository,
# the compiled binary, and the Perl checkout the tests are borrowed from -- and
# puts the Perl checkout's library directories on @INC.
#
# `use ConformancePaths;` has to come before any `use` of a module that lives in
# the Perl checkout (RawSMTPClient, SMTPProxy::SMTPServer, Mojo::*), because the
# import below is what makes those findable. That is why the tests call it in a
# `use` and not at runtime.
#
# Paths are derived from __FILE__ rather than FindBin, so that the answer does
# not depend on which script happens to be running.

use strict;
use warnings;
use File::Basename qw(dirname);
use File::Spec;
use Cwd qw(abs_path);

# conformance/lib/ConformancePaths.pm -> the repository root two levels up.
my $REPO = abs_path(File::Spec->catdir(dirname(__FILE__), File::Spec->updir, File::Spec->updir));

sub repo_root { return $REPO }

# The Perl proxy is the binding authority for wire format, reply texts, API JSON
# and log formats, so the tests are run against its own checkout rather than
# against a vendored copy that could drift from it.
#
# SMTP_PROXY_PERL wins, because a git worktree of the Rust repository does not
# sit beside the Perl one and the sibling guess is then wrong.
sub perl_root {
    if (my $env = $ENV{SMTP_PROXY_PERL}) {
        die "SMTP_PROXY_PERL is set to '$env', which is not a directory\n"
            unless -d $env;
        return abs_path($env);
    }
    my $sibling = File::Spec->catdir($REPO, File::Spec->updir, 'smtp-proxy');
    return abs_path($sibling) if -d $sibling;
    die "Cannot find the Perl smtp-proxy checkout. Tried \$SMTP_PROXY_PERL "
        . "(unset) and the sibling '$sibling'. Set SMTP_PROXY_PERL to the "
        . "checkout root.\n";
}

# CARGO_TARGET_DIR is set in some environments and unset in others, and when it
# is set `<repo>/target` does not exist at all. All three candidates are tried
# before giving up, and the failure names every one of them so that the fix is
# obvious from the message alone.
sub binary {
    my @tried;
    if (my $env = $ENV{SMTP_PROXY_BIN}) {
        return $env if -x $env;
        push @tried, "\$SMTP_PROXY_BIN=$env";
    }
    if (my $dir = $ENV{CARGO_TARGET_DIR}) {
        my $path = File::Spec->catfile($dir, 'debug', 'smtp-proxy');
        return $path if -x $path;
        push @tried, $path;
    }
    my $default = File::Spec->catfile($REPO, 'target', 'debug', 'smtp-proxy');
    return $default if -x $default;
    push @tried, $default;
    die "Cannot find the smtp-proxy binary. Tried: " . join(', ', @tried)
        . ". Build it with `cargo build`, or set SMTP_PROXY_BIN.\n";
}

# The test certificate and key, taken from the Perl checkout so that both
# suites present the same certificate.
sub certs { return File::Spec->catdir(perl_root(), 't', 'certs-and-keys') }

# `lib->import` rather than a bare unshift, because thirdparty/lib/perl5 carries
# an architecture subdirectory holding the XS parts of Mojolicious, and lib.pm
# is what knows to add it.
sub import {
    my $root = perl_root();
    require lib;
    lib->import(
        File::Spec->catdir($root, 't'),
        File::Spec->catdir($root, 'lib'),
        File::Spec->catdir($root, 'thirdparty', 'lib', 'perl5'),
    );
    return;
}

1;
