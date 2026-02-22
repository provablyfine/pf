NULL:=

DOCS := \
 security.md \
 $(NULL)

ROOT_DIR := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))
CPUS := $(shell nproc 2>/dev/null || echo 4)
export PYTHONUNBUFFERED=1

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
	uv run pytest --tb=short
tests-fast:
	@echo $(CPUS)
	@uv run pytest --co -q | head -n -2 | \
		parallel -j$(CPUS) --halt now,fail=1 --bar --eta --will-cite \
		'printf "%-80s" "{}..."; \
		output=$$(uv run pytest {} --tb=short -q 2>&1); \
		if [ $$? -ne 0 ]; then \
			echo " FAILED"; \
			echo "$$output"; \
			exit 1; \
		else \
			echo " PASSED"; \
		fi'

cov:
	COVERAGE_FILE=$(shell pwd)/.coverage COVERAGE_PROCESS_START=$(shell pwd)/tests/.coveragerc COVERAGE_RCFILE=$(shell pwd)/tests/.coveragerc uv run pytest --tb=short

cov-report:
	@coverage combine -a -q || true
	coverage html -d cov
	coverage report

clean:
	rm -f tests/tmp*.t >/dev/null 2>&1

.PHONY: tests cov cov-report clean tests-fast
