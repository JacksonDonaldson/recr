# Build the codezip sample input: a 37-function, non-PIE x86-64 ELF with
# full debug information.  -O0 keeps every function as a separate symbol.

CC ?= cc
CFLAGS ?= -m64 -O0 -g3 -fno-omit-frame-pointer -fno-inline \
          -fno-pie -Wall -Wextra -Wpedantic
LDFLAGS ?= -m64 -no-pie
LDLIBS ?=
NASM ?= nasm

BUILD_DIR := build
TARGET := $(BUILD_DIR)/sample
SOURCE := sample.c
RED_ZONE_SOURCE := optimizers/red_zone_outline.s
RED_ZONE_OBJECT := $(BUILD_DIR)/red_zone_outline.o

# Ghidra headless export.  Override GHIDRA_HOME if Ghidra lives elsewhere.
GHIDRA_HOME ?= $(HOME)/opt/ghidra
GHIDRA_PROJECT_DIR ?= /tmp/opencode/ghidra_projects
GHIDRA_PROJECT ?= codezip_sample
GHIDRA_XML := $(BUILD_DIR)/sample_ghidra.xml

.PHONY: all run ghidra-xml e2e e2e-mutation clean

all: $(TARGET) $(RED_ZONE_OBJECT)

$(TARGET): $(SOURCE) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SOURCE) $(LDFLAGS) $(LDLIBS) -o $@

# Red-zone outlining fixture; the test reads function bounds from its symbols.
$(RED_ZONE_OBJECT): $(RED_ZONE_SOURCE) | $(BUILD_DIR)
	$(NASM) -f elf64 $< -o $@

$(BUILD_DIR):
	mkdir -p $@

run: $(TARGET)
	./$(TARGET)

ghidra-xml: $(TARGET)
	mkdir -p $(GHIDRA_PROJECT_DIR)
	$(GHIDRA_HOME)/support/analyzeHeadless \
		$(GHIDRA_PROJECT_DIR) $(GHIDRA_PROJECT) \
		-import $(abspath $(TARGET)) \
		-scriptPath $(CURDIR)/ghidra_scripts \
		-postScript ExportGhidraXml.java $(abspath $(GHIDRA_XML)) \
		-analysisTimeoutPerFile 300 \
		-deleteProject

# Opt-in end-to-end check: builds pinned pcre2, rewrites its test executables
# with codezip, and re-runs pcre2's suite plus the pcre2grep library corpus.
# See test/e2e/README.md.
e2e:
	$(CURDIR)/e2e/run_e2e.py

# Opt-in mutation check: flip bytes in the codezipped binaries and require the
# pcre2 suite to notice.  Needs the artifacts from `make e2e`.
e2e-mutation:
	$(CURDIR)/e2e/mutation_check.py

clean:
	rm -rf $(BUILD_DIR)
