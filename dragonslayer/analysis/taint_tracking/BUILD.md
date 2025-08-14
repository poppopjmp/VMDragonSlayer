# VMDragonTaint Build Guide

VMDragonTaint is a dynamic taint tracking Pin tool designed for analyzing VM-protected binaries. This guide covers building the tool on both Linux and Windows platforms.

## Prerequisites

### Common Requirements
- Intel Pin framework (3.7 or later recommended)
- C++11 compatible compiler
- Make utility (for Makefile builds)

### Linux/macOS
- GCC 7+ or Clang 6+ with C++11 support
- POSIX-compliant development environment
- pthreads library

### Windows
- Visual Studio 2017+ with MSVC compiler, OR
- MinGW-w64 with GCC 7+
- Windows SDK (for Visual Studio builds)

## Installation

### 1. Install Intel Pin

#### Linux/macOS
```bash
# Download Pin from Intel's website
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz
tar -xzf pin-3.28-*.tar.gz
export PIN_ROOT=/path/to/pin-3.28-*
```

#### Windows
```cmd
REM Download Pin from Intel's website
REM Extract to C:\intel\pin (or preferred location)
set PIN_ROOT=C:\intel\pin
```

### 2. Verify Pin Installation
```bash
# Linux/macOS
$PIN_ROOT/pin -help

# Windows
%PIN_ROOT%\pin.exe -help
```

## Building VMDragonTaint

### Method 1: Using Makefile (Linux/macOS/Windows with MSYS2)

```bash
# Set environment
export PIN_ROOT=/path/to/pin  # Linux/macOS
# set PIN_ROOT=C:\intel\pin   # Windows

# Validate environment
make validate

# Build the tool
make

# Build with debug symbols
make debug

# Run tests
make test

# Clean build artifacts
make clean
```

### Method 2: Windows Batch Script

```cmd
REM Set environment
set PIN_ROOT=C:\intel\pin

REM Build using batch script
build_windows.bat
```

### Method 3: Manual Build

#### Linux/macOS Manual Build
```bash
export PIN_ROOT=/path/to/pin
mkdir -p obj-intel64

g++ -std=c++11 -O2 -g -fPIC -pthread \
    -I$PIN_ROOT/source/include/pin \
    -I$PIN_ROOT/source/include/pin/gen \
    -shared -o obj-intel64/VMDragonTaint.so \
    VMDragonTaint.cpp \
    -L$PIN_ROOT/intel64/lib \
    -L$PIN_ROOT/intel64/lib-ext \
    -lpin -lxed -lpindwarf -ldl
```

#### Windows Manual Build (MinGW)
```cmd
set PIN_ROOT=C:\intel\pin
mkdir obj-intel64

g++ -std=c++11 -O2 -g -D_WIN32 -DWIN32_LEAN_AND_MEAN ^
    -I"%PIN_ROOT%\source\include\pin" ^
    -I"%PIN_ROOT%\source\include\pin\gen" ^
    -shared -o obj-intel64\VMDragonTaint.dll ^
    VMDragonTaint.cpp ^
    -L"%PIN_ROOT%\intel64\lib" ^
    -L"%PIN_ROOT%\intel64\lib-ext" ^
    -lpin -lxed -lpindwarf
```

#### Windows Manual Build (Visual Studio)
```cmd
set PIN_ROOT=C:\intel\pin
mkdir obj-intel64

cl /std:c++11 /O2 /D_WIN32 /DWIN32_LEAN_AND_MEAN ^
   /I"%PIN_ROOT%\source\include\pin" ^
   /I"%PIN_ROOT%\source\include\pin\gen" ^
   /LD VMDragonTaint.cpp ^
   /Fe:obj-intel64\VMDragonTaint.dll ^
   /link /LIBPATH:"%PIN_ROOT%\intel64\lib" ^
   pin.lib xed.lib
```

## Cross-Platform Differences

### File Extensions
- Linux/macOS: `.so` (shared object)
- Windows: `.dll` (dynamic link library)

### Path Separators
- Linux/macOS: `/` (forward slash)
- Windows: `\` (backslash)

### Threading
- Linux/macOS: pthreads
- Windows: Windows threading API (handled by Pin)

### Build Tools
- Linux/macOS: GCC/Clang with Make
- Windows: MSVC/MinGW with Make/Batch scripts

## Usage

### Basic Usage
```bash
# Linux/macOS
$PIN_ROOT/pin -t obj-intel64/VMDragonTaint.so -o taint.log -- ./target_binary

# Windows
%PIN_ROOT%\pin.exe -t obj-intel64\VMDragonTaint.dll -o taint.log -- target_binary.exe
```

### Command Line Options
- `-o <file>`: Output log file (default: taint.log)
- `-taint_start <addr>`: Start address of taint range (hex)
- `-taint_end <addr>`: End address of taint range (hex)
- `-image <name>`: Filter instrumentation to specific image
- `-trace_handlers <addrs>`: Comma-separated handler addresses to trace
- `-trace_dir <dir>`: Directory for handler trace files
- `-timeout <seconds>`: Analysis timeout in seconds

### Example with Options
```bash
# Linux/macOS
$PIN_ROOT/pin -t obj-intel64/VMDragonTaint.so \
  -o vm_analysis.log \
  -taint_start 0x401000 \
  -taint_end 0x402000 \
  -trace_handlers 0x12345678,0x87654321 \
  -timeout 300 \
  -- ./protected_binary

# Windows
%PIN_ROOT%\pin.exe -t obj-intel64\VMDragonTaint.dll ^
  -o vm_analysis.log ^
  -taint_start 0x401000 ^
  -taint_end 0x402000 ^
  -trace_handlers 0x12345678,0x87654321 ^
  -timeout 300 ^
  -- protected_binary.exe
```

## Troubleshooting

### Common Build Issues

#### "pin.H not found"
- Verify PIN_ROOT is set correctly
- Check Pin installation integrity
- Ensure include paths are correct

#### "undefined reference to PIN_*"
- Missing Pin libraries in link command
- Incorrect library path
- Architecture mismatch (32-bit vs 64-bit)

#### Windows-specific: "MSVCR*.dll not found"
- Install Visual C++ Redistributable
- Use static linking with `/MT` flag
- Ensure correct MSVC version compatibility

### Runtime Issues

#### "Pin tool failed to load"
- Architecture mismatch (tool vs target binary)
- Missing dependencies
- Incorrect Pin version

#### "Access denied" on Windows
- Run as Administrator
- Check antivirus software interference
- Verify target binary permissions

### Performance Issues

#### High memory usage
- Reduce taint range size
- Increase timeout value
- Use image filtering to reduce instrumentation scope

#### Slow execution
- Use release build (`make` instead of `make debug`)
- Optimize taint tracking granularity
- Consider selective instrumentation

## Output Format

### Log File Structure
```
VMDRAGON_TAINT_START: pid=1234 time=1640995200 timeout=300
IMAGE_LOAD: target_binary base=0x400000 size=0x10000
TAINT_INIT: range=0x401000:0x402000
TAINTED_READ: ip=0x401234 addr=0x401100 size=4 taint=0x1
TAINTED_WRITE: ip=0x401238 addr=0x7fff1000 size=4 taint=0x1
TAINTED_REG: ip=0x40123c reg=EAX taint=0x1
TAINTED_JUMP: ip=0x401240 target=0x12345678 taint=0x1
HANDLER_CALL: ip=0x401240 handler=0x12345678 count=1000
ANALYSIS_COMPLETE:
  instructions=50000
  tainted_ops=150
  indirect_jumps=25
  exit_code=0
  runtime=30s
```

### Handler Trace Files
Individual trace files are created for each monitored handler:
- `handler_12345678.trace`
- `handler_87654321.trace`

## Integration with VMDragonSlayer

The taint tracking tool integrates with the VMDragonSlayer framework through:

1. **Configuration**: `data/taint_config.properties`
2. **Python Interface**: `vm_taint_tracker.py`
3. **Analysis Pipeline**: Orchestrated through the main framework

### Configuration Integration
```python
# In VMDragonSlayer Python code
from dragonslayer.analysis.taint_tracking import VMTaintTracker

tracker = VMTaintTracker()
result = tracker.analyze_binary("protected_binary.exe", {
    'taint_start': 0x401000,
    'taint_end': 0x402000,
    'timeout': 300
})
```

## Development

### Adding New Features
1. Modify `VMDragonTaint.cpp`
2. Update command line options if needed
3. Test on both Linux and Windows
4. Update documentation

### Debug Build
```bash
make debug  # Enables debug symbols and verbose output
```

### Code Style
- Follow Intel Pin coding conventions
- Use C++11 features consistently
- Maintain cross-platform compatibility
- Add comprehensive error handling

## License

This tool is part of the VMDragonSlayer framework and is licensed under GPL v3.0.
