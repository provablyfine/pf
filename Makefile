NULL:=

IDB_TESTS := \
 idb-tags.t \
 idb-boundaries.t \
 idb-roles.t \
 idb-identity.t \
 idb-permission.t \
 idb-access-control.t \
 idb-access-control-tag.t \
 $(NULL)

SSH_TESTS := \
 ssh-keys.t \
 ssh-certificates.t \
 ssh-ecdsa-certificates.t \
 $(NULL)

SSH_AGENT_TESTS := \
 ssh-agent-keys.t \
 $(NULL)

DOCS := \
 security.md \
 $(NULL)

ROOT_DIR := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))


IDB_TEST_TARGETS=$(addprefix tests/,$(IDB_TESTS:.t=.test))
SSH_AGENT_TEST_TARGETS=$(addprefix tests/,$(SSH_AGENT_TESTS:.t=.test))
SSH_TEST_TARGETS=$(addprefix tests/,$(SSH_TESTS:.t=.test))
TEST_TARGETS=$(IDB_TEST_TARGETS) $(SSH_TEST_TARGETS) $(SSH_AGENT_TEST_TARGETS)
DOC_TARGETS=$(addprefix docs/,$(DOCS:.md=.html))

%.t: %.t.jinja
	jinja2 $^ > $@

PANDOC_ARGS := \
 --standalone \
 --toc \
 --toc-depth=3 \
 --template=template.html \
 --highlight-style pygments \
 $(NULL)

all:

~/.pandoc/templates:
	mkdir -p $@
~/.pandoc/templates/template.html: docs/template.html ~/.pandoc/templates
	cp $< $@

$(DOC_TARGETS): %.html: %.md Makefile ~/.pandoc/templates/template.html
	pandoc $< -t html -o $@ $(PANDOC_ARGS)

docs: $(DOC_TARGETS)

tests: $(IDB_TEST_TARGETS)

$(SSH_AGENT_TEST_TARGETS): tests/ssh-agent-%.test: tests/ssh-agent-%.t
	@echo cram $<
	@PATH=$$PATH:$(ROOT_DIR)/scripts ./tests/ssh-agent-test.sh $<

$(IDB_TEST_TARGETS): tests/idb-%.test: tests/idb-%.t
	@echo cram $<
	@PATH=$$PATH:$(ROOT_DIR)/scripts ./tests/idb-test.sh $<

$(SSH_TEST_TARGETS): tests/ssh-%.test: tests/ssh-%.t
	@echo cram $<
	@PATH=$$PATH:$(ROOT_DIR)/scripts cram $<

.PHONY: $(TEST_TARGETS) tests
