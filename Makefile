NULL:=

TESTS := \
 tags.t \
 boundaries.t \
 roles.t \
 permission.t \
 access-control.t \
 $(NULL)

DOCS := \
 security.md \
 $(NULL)

ROOT_DIR := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))


TEST_TARGETS=$(addprefix tests/,$(addsuffix .test,$(basename $(strip $(TESTS)))))
DOC_TARGETS=$(addprefix docs/,$(addsuffix .html,$(basename $(strip $(DOCS)))))

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

tests: $(TEST_TARGETS)

$(TEST_TARGETS): %.test: %.t
	@echo cram $<
	@PATH=$$PATH:$(ROOT_DIR)/scripts ./tests/run-test.sh $<

.PHONY: $(TEST_TARGETS) tests
