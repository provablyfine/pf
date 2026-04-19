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
	PYTHONUNBUFFERED=1 uv run pytest --tb=short -n auto
cov:
	@rm -rf .coverage
	PYTHONUNBUFFERED=1 COVERAGE_FILE=$(shell pwd)/.coverage COVERAGE_PROCESS_START=$(shell pwd)/tests/.coveragerc COVERAGE_RCFILE=$(shell pwd)/tests/.coveragerc uv run pytest --tb=short -n auto

cov-report:
	@coverage combine -a -q || true
	coverage html -d cov
	coverage report

check: tests check-imports format

check-imports:
	./scripts/check-imports

format:
	uv run ruff format
	uv run ruff check

.PHONY: tests cov cov-report check-imports format check
