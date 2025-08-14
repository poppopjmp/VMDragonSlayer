# VMDragonTaint Pin Tool Makefile
# Builds the dynamic taint tracking Pin tool for VMDragonSlayer

# Configuration
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

# Tool configuration
TOOL_ROOTS := VMDragonTaint
TOOL_CXXFLAGS += -std=c++11 -O2 -g
TOOL_LDFLAGS += 

# Source files
VMDragonTaint_SOURCES := VMDragonTaint.cpp

# Build targets
all: obj-intel64/VMDragonTaint.so

obj-intel64/VMDragonTaint.so: VMDragonTaint.cpp
	@mkdir -p obj-intel64
	$(CXX) $(TOOL_CXXFLAGS) $(COMP_OBJ)$@ $< $(TOOL_LDFLAGS) $(TOOL_LPATHS) $(TOOL_LIBS)

# Development targets
debug: TOOL_CXXFLAGS += -DDEBUG -O0
debug: obj-intel64/VMDragonTaint.so

clean:
	rm -rf obj-intel64

install: obj-intel64/VMDragonTaint.so
	@echo "Pin tool built successfully: obj-intel64/VMDragonTaint.so"
	@echo "Usage: $(PIN_ROOT)/pin -t obj-intel64/VMDragonTaint.so [options] -- <target_binary>"

test: obj-intel64/VMDragonTaint.so
	@echo "Running basic test..."
	$(PIN_ROOT)/pin -t obj-intel64/VMDragonTaint.so -o test_output.log -- /bin/echo "VMDragonTaint test"
	@echo "Test completed. Check test_output.log for results."

# Help target
help:
	@echo "VMDragonTaint Pin Tool Build System"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Intel Pin framework installed"
	@echo "  - PIN_ROOT environment variable set"
	@echo "  - GCC/G++ with C++11 support"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build the Pin tool (default)"
	@echo "  debug   - Build with debug symbols"
	@echo "  clean   - Clean build artifacts"
	@echo "  install - Build and show usage information"
	@echo "  test    - Build and run a basic test"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  PIN_ROOT - Path to Intel Pin installation (required)"
	@echo ""
	@echo "Example usage:"
	@echo "  export PIN_ROOT=/opt/intel/pin"
	@echo "  make"
	@echo "  $(PIN_ROOT)/pin -t obj-intel64/VMDragonTaint.so -o results.log -- ./target_binary"

.PHONY: all debug clean install test help
