CC ?= gcc
PYTHON ?= python3

BUILD_DIR := build
BUILD_STAMP := $(BUILD_DIR)/.dir
SOURCE := target/broker.c
HEADERS := target/protocol.h
VULNERABLE := $(BUILD_DIR)/deadletterd
FIXED := $(BUILD_DIR)/deadletterd-fixed

HARDEN_CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Wpedantic \
	-fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2
HARDEN_LDFLAGS := -pie -Wl,-z,relro,-z,now,-z,noexecstack
LAB_CPPFLAGS := -DLAB_MODE=1

.DEFAULT_GOAL := build

.PHONY: build fixed check demo reliability cleanup reset clean

build: $(VULNERABLE)

fixed: $(FIXED)

$(BUILD_STAMP):
	mkdir -p $(BUILD_DIR)
	touch $@

$(VULNERABLE): $(SOURCE) $(HEADERS) | $(BUILD_STAMP)
	$(CC) $(CPPFLAGS) $(LAB_CPPFLAGS) $(CFLAGS) $(HARDEN_CFLAGS) $< \
		-o $@ $(LDFLAGS) $(HARDEN_LDFLAGS) $(LDLIBS)

$(FIXED): $(SOURCE) $(HEADERS) | $(BUILD_STAMP)
	$(CC) $(CPPFLAGS) $(LAB_CPPFLAGS) -DFIXED=1 $(CFLAGS) $(HARDEN_CFLAGS) $< \
		-o $@ $(LDFLAGS) $(HARDEN_LDFLAGS) $(LDLIBS)

check: build fixed
	$(PYTHON) tools/lab.py check

demo: build
	$(PYTHON) tools/lab.py demo --binary $(VULNERABLE)

reliability: build
	$(PYTHON) tools/lab.py reliability --runs 25

cleanup:
	$(PYTHON) tools/lab.py cleanup

reset: clean cleanup

clean:
	rm -rf -- $(BUILD_DIR) .lab
