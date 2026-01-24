TESTS := \
 tags.t
ROOT_DIR := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

TEST_TARGETS=$(addprefix tests/,$(addsuffix .test,$(basename $(strip $(TESTS)))))

tests: $(TEST_TARGETS)

$(TEST_TARGETS): %.test: %.t
	PATH=$$PATH:$(ROOT_DIR)/scripts ./tests/run-test.sh $<

.PHONY: $(TEST_TARGETS) tests
