# The Perl conformance gate. Runs the original suite's tests against the
# compiled binary over a real socket. `make conformance` at the top level
# builds first and then calls this.

# Where the Perl smtp-proxy checkout lives. It is the binding authority for
# wire format, reply texts, API JSON and log formats, and the tests borrow its
# helper modules and its test certificate, so the suite cannot run without it.
#
# Computed rather than hardcoded, and exported, so that a bare `make
# conformance` works from a git worktree as well as from a main checkout.
#
# A main checkout sits beside the Perl one, so the sibling is the answer there.
# A worktree does not sit beside anything -- it lives wherever it was created --
# so the fallback asks git for the repository this worktree belongs to and
# looks beside *that*. `--git-common-dir` is the .git of the main checkout even
# when run from a worktree; its parent is the checkout, and the Perl one is its
# sibling. It may answer relatively, which is why the shell starts from the
# repository root.
#
# `wildcard` keeps only the candidates that exist, so an unbuilt guess never
# wins over a real directory. Override on the command line when neither guess
# is right:
#
#   make conformance SMTP_PROXY_PERL=/path/to/smtp-proxy
SIBLING_GUESS := $(abspath ../../smtp-proxy)
MAIN_CHECKOUT := $(shell d=$$(git -C .. rev-parse --git-common-dir 2>/dev/null) \
                   && cd .. && cd "$$d/.." 2>/dev/null && pwd)
WORKTREE_GUESS := $(if $(MAIN_CHECKOUT),$(abspath $(MAIN_CHECKOUT)/../smtp-proxy))
SMTP_PROXY_PERL ?= $(firstword $(wildcard $(SIBLING_GUESS) $(WORKTREE_GUESS)))
export SMTP_PROXY_PERL

# Kept modest on purpose: every test file spawns a proxy process and binds
# several sockets, so this is a load setting, not a speed setting.
JOBS ?= 4

.PHONY: test
test:
	@test -d "$(SMTP_PROXY_PERL)" || { \
	  echo "conformance: the Perl checkout '$(SMTP_PROXY_PERL)' does not exist."; \
	  echo "conformance: set SMTP_PROXY_PERL to the smtp-proxy checkout root."; \
	  exit 1; }
	prove -w -j $(JOBS) -Ilib t/
