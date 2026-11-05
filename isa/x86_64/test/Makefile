# Assemble the minimal x86-64 instruction fixture with NASM.

NASM ?= nasm
NASMFLAGS ?= -f bin

BUILD_DIR := build
TARGET := $(BUILD_DIR)/test.bin
SOURCE := test.s

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE) | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) $(SOURCE) -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
