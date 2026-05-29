NULL:=

tests:
	PYTHONUNBUFFERED=1 uv run pytest --tb=short -n auto
cov:
	@rm -rf .coverage
	PYTHONUNBUFFERED=1 COVERAGE_FILE=$(shell pwd)/.coverage COVERAGE_PROCESS_START=$(shell pwd)/tests/.coveragerc COVERAGE_RCFILE=$(shell pwd)/tests/.coveragerc uv run pytest --tb=short -n auto

cov-report:
	coverage combine --rcfile $(shell pwd)/tests/.coveragerc -a -q || true
	coverage html -d cov --rcfile $(shell pwd)/tests/.coveragerc
	coverage report

lint:
	uv run pre-commit run -a

check: lint tests

.PHONY: tests cov cov-report lint check
