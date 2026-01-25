NULL:=
TESTS := \
 tags.t \
 boundaries.t \
 roles.t \
 $(NULL)
ROOT_DIR := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

TEST_TARGETS=$(addprefix tests/,$(addsuffix .test,$(basename $(strip $(TESTS)))))

tests: $(TEST_TARGETS)

$(TEST_TARGETS): %.test: %.t
	@echo cram $<
	@PATH=$$PATH:$(ROOT_DIR)/scripts ./tests/run-test.sh $<

.PHONY: $(TEST_TARGETS) tests
