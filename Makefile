NULL:=

DOCS := \
 security.md \
 $(NULL)

ROOT_DIR := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))


DOC_TARGETS=$(addprefix docs/,$(DOCS:.md=.html))

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

tests:
	uv run pytest --tb=short -n auto

cov:
	COVERAGE_FILE=$(shell pwd)/.coverage COVERAGE_PROCESS_START=$(shell pwd)/tests/.coveragerc COVERAGE_RCFILE=$(shell pwd)/tests/.coveragerc uv run pytest --tb=short -n auto

.PHONY: tests cov
