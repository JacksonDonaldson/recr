# Assemble the x86-64 instruction fixtures with NASM.

NASM ?= nasm
NASMFLAGS ?= -f bin
PYTHON ?= python

BUILD_DIR := build
SOURCES := test.s opcodes.s
TARGETS := $(patsubst %.s,$(BUILD_DIR)/%.bin,$(SOURCES))
INTEL_FORMS := intel_64bit_forms.txt
INTEL_CASES := $(BUILD_DIR)/intel_cases.json
INTEL_STATE := intel_state_effects.json

.PHONY: all clean state-golden

all: $(TARGETS) $(INTEL_CASES)

$(BUILD_DIR)/%.bin: %.s | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) $< -o $@

$(INTEL_CASES): intel_cases.py $(INTEL_FORMS) | $(BUILD_DIR)
	$(PYTHON) intel_cases.py $(INTEL_FORMS) $@

state-golden: $(INTEL_CASES) generate_intel_state.py
	$(PYTHON) generate_intel_state.py $(INTEL_CASES) $(INTEL_STATE)

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
