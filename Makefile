NULL:=

tests:
	PYTHONUNBUFFERED=1 uv run pytest
cov:
	@rm -rf .coverage
	PYTHONUNBUFFERED=1 COVERAGE_PROCESS_START=$(shell pwd)/pyproject.toml uv run pytest

cov-report:
	uv run coverage combine --rcfile $(shell pwd)/pyproject.toml -a -q || true
	uv run coverage html -d cov --rcfile $(shell pwd)/pyproject.toml
	uv run coverage report

mutants:
	./scripts/check-mutation-baseline

lint:
	uv run pre-commit run -a

check: lint tests mutants

.PHONY: tests cov cov-report lint check mutants
