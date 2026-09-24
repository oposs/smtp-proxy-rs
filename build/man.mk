# repo-infra: man v1
#
# The man page, built from docs/manual.md (D23).
#
# docs/manual.md is the one source. pandoc converts it to man/$(MAN_NAME).1 on
# demand, and man/ belongs in .gitignore: a generated page under version
# control can disagree with its source. build/man-deflist.lua turns the
# manual's "- `--option`: text" bullet lists into definition lists, so the page
# gets .TP entries while GitHub still renders the source as lists.
#
# repo-infra owns this file. Include it from the Makefile after naming the page:
#
#     MAN_NAME = mytool
#     include build/man.mk
#
# The page's date comes from `date:` in the manual's front matter, never from
# the build, so two builds of one source produce the same page.
#
# The include may go anywhere in the Makefile; it saves and restores
# .DEFAULT_GOAL so that adding this fragment never makes `man` the target a
# bare `make` builds.

ifeq ($(strip $(MAN_NAME)),)
$(error MAN_NAME is not set: set it before `include build/man.mk`, for example MAN_NAME = mytool)
endif

_repo_infra_man_goal := $(.DEFAULT_GOAL)

.PHONY: man
man: man/$(MAN_NAME).1

man/$(MAN_NAME).1: docs/manual.md build/man-deflist.lua
	@mkdir -p man
	pandoc --standalone --to man --lua-filter build/man-deflist.lua \
	  docs/manual.md -o $@

.DEFAULT_GOAL := $(_repo_infra_man_goal)
