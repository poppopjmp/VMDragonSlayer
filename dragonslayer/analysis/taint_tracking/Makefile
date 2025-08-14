# VMDragonTaint Pin Tool Makefile
# Builds the dynamic taint tracking Pin tool for VMDragonSlayer
# Supports both Linux and Windows builds

# Platform detection
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
    TOOL_EXT := .so
    CLEAN_CMD := rm -rf
    MKDIR_CMD := mkdir -p
endif
ifeq ($(UNAME_S),Darwin)
    PLATFORM := mac
    TOOL_EXT := .dylib
    CLEAN_CMD := rm -rf
    MKDIR_CMD := mkdir -p
endif
ifeq ($(UNAME_S),Windows)
    PLATFORM := windows
    TOOL_EXT := .dll
    CLEAN_CMD := del /Q /S
    MKDIR_CMD := mkdir
endif

# Configuration
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

# Tool configuration
TOOL_ROOTS := VMDragonTaint
TOOL_CXXFLAGS += -std=c++11 -O2 -g -Wall -Wextra
ifeq ($(PLATFORM),linux)
    TOOL_CXXFLAGS += -fPIC -pthread
    TOOL_LDFLAGS += -pthread
endif
ifeq ($(PLATFORM),windows)
    TOOL_CXXFLAGS += -D_WIN32 -DWIN32_LEAN_AND_MEAN
endif

# Source files
VMDragonTaint_SOURCES := VMDragonTaint.cpp

# Build targets
all: obj-intel64/VMDragonTaint$(TOOL_EXT)

obj-intel64/VMDragonTaint$(TOOL_EXT): VMDragonTaint.cpp
	@$(MKDIR_CMD) obj-intel64
	$(CXX) $(TOOL_CXXFLAGS) $(COMP_OBJ)$@ $< $(TOOL_LDFLAGS) $(TOOL_LPATHS) $(TOOL_LIBS)

# Development targets
debug: TOOL_CXXFLAGS += -DDEBUG -O0 -g3
debug: obj-intel64/VMDragonTaint$(TOOL_EXT)

clean:
ifeq ($(PLATFORM),windows)
	if exist obj-intel64 $(CLEAN_CMD) obj-intel64\*
	if exist obj-intel64 rmdir obj-intel64
else
	$(CLEAN_CMD) obj-intel64
endif

install: obj-intel64/VMDragonTaint$(TOOL_EXT)
	@echo "Pin tool built successfully: obj-intel64/VMDragonTaint$(TOOL_EXT)"
	@echo "Platform: $(PLATFORM)"
	@echo "Usage: $(PIN_ROOT)/pin -t obj-intel64/VMDragonTaint$(TOOL_EXT) [options] -- <target_binary>"

test: obj-intel64/VMDragonTaint$(TOOL_EXT)
	@echo "Running basic test on $(PLATFORM)..."
ifeq ($(PLATFORM),windows)
	$(PIN_ROOT)\pin.exe -t obj-intel64\VMDragonTaint$(TOOL_EXT) -o test_output.log -- cmd.exe /c echo VMDragonTaint test
else
	$(PIN_ROOT)/pin -t obj-intel64/VMDragonTaint$(TOOL_EXT) -o test_output.log -- /bin/echo "VMDragonTaint test"
endif
	@echo "Test completed. Check test_output.log for results."

# Cross-platform validation
validate:
	@echo "Validating build environment..."
	@echo "Platform: $(PLATFORM)"
	@echo "PIN_ROOT: $(PIN_ROOT)"
	@echo "Tool extension: $(TOOL_EXT)"
ifeq ($(PIN_ROOT),)
	@echo "ERROR: PIN_ROOT environment variable not set"
	@exit 1
endif
	@echo "Environment validation passed."

# Help target
help:
	@echo "VMDragonTaint Pin Tool Build System"
	@echo ""
	@echo "Platform: $(PLATFORM)"
	@echo "Tool Extension: $(TOOL_EXT)"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Intel Pin framework installed"
	@echo "  - PIN_ROOT environment variable set"
	@echo "  - GCC/G++ with C++11 support (Linux/Mac)"
	@echo "  - Visual Studio or MinGW (Windows)"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the Pin tool (default)"
	@echo "  debug     - Build with debug symbols and verbose output"
	@echo "  clean     - Clean build artifacts"
	@echo "  install   - Build and show usage information"
	@echo "  test      - Build and run a basic test"
	@echo "  validate  - Validate build environment"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  PIN_ROOT  - Path to Intel Pin installation (required)"
	@echo ""
	@echo "Example usage (Linux/Mac):"
	@echo "  export PIN_ROOT=/opt/intel/pin"
	@echo "  make"
	@echo "  $$(PIN_ROOT)/pin -t obj-intel64/VMDragonTaint$(TOOL_EXT) -o results.log -- ./target_binary"
	@echo ""
	@echo "Example usage (Windows):"
	@echo "  set PIN_ROOT=C:\\intel\\pin"
	@echo "  make"
	@echo "  %PIN_ROOT%\\pin.exe -t obj-intel64\\VMDragonTaint$(TOOL_EXT) -o results.log -- target_binary.exe"

.PHONY: all debug clean install test help validate
