# Getting Started with DragonSlayer-RS

## Overview

DragonSlayer-RS is the Rust port of VMDragonSlayer, an automated multi-engine framework for unpacking, analyzing, and devirtualizing binaries protected by VM-based protectors.

## Prerequisites

- Rust 1.74+ (1.80+ recommended for full feature support)
- Git
- Basic understanding of Rust

## Building the Project

### First Time Setup

```bash
cd dragonslayer-rs
cargo build
```

### Development Mode

```bash
# Build and run tests
cargo test

# Run with debug output
RUST_LOG=debug cargo run

# Check code without building
cargo check

# Build optimized release
cargo build --release
```

### Current Build Status

✅ **Building successfully** with basic dependencies:
- Core error handling
- Configuration framework
- VM Discovery module structure
- Pattern Analysis module structure
- Serde serialization
- Tokio async runtime

⚠️ **Not yet implemented:**
- Full analysis engines
- Intel Pin integration
- Z3 symbolic execution
- API server
- ML components
- Workflow management

## Project Structure

```
dragonslayer-rs/
├── src/
│   ├── core/               # Core infrastructure
│   │   ├── error.rs        # Error types ✅
│   │   └── config.rs       # Configuration ✅
│   ├── analysis/           # Analysis engines
│   │   ├── vm_discovery/   # VM detection (stub) ✅
│   │   └── pattern_analysis/ # Pattern matching (stub) ✅
│   ├── lib.rs              # Library entry ✅
│   └── main.rs             # Main executable ✅
├── Cargo.toml              # Project config ✅
├── RUST_PORT_PLAN.md        # Comprehensive plan ✅
├── README.md                # Project docs ✅
└── MIGRATION_SUMMARY.md     # Status summary ✅
```

## Current Implementation Status

### Phase 1: Foundation ✅ COMPLETE

- [x] Project structure
- [x] Core error types (`core/error.rs`)
- [x] Configuration system (`core/config.rs`)
- [x] VM Discovery types (`analysis/vm_discovery/mod.rs`)
- [x] Pattern Analysis types (`analysis/pattern_analysis/mod.rs`)
- [x] Module organization
- [x] Basic documentation

### Next Steps (Phase 2)

1. **Implement VM Detection Logic** (4-6 weeks)
   - Dispatcher detection algorithms
   - Handler table analysis
   - Control flow heuristics
   - Parallel pattern matching

2. **Implement Pattern Recognition** (3-4 weeks)
   - Pattern database loading
   - Matching algorithms
   - Confidence scoring
   - SIMD acceleration

3. **Add Comprehensive Tests** (ongoing)
   - Unit tests for all modules
   - Integration tests with sample binaries
   - Performance benchmarks

## Usage Examples

### Basic Example (Future)

```rust
use dragonslayer_rs::*;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = Config::default();
    
    // Create VM detector
    let detector = VMDetector::new();
    
    // Analyze binary
    let binary = std::fs::read("sample.exe")?;
    let result = detector.detect_vm(&binary)?;
    
    println!("VM Type: {:?}", result.vm_type);
    println!("Confidence: {:.2}%", result.confidence * 100.0);
    
    Ok(())
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_vm_detector_creation

# Run with output
cargo test -- --nocapture
```

## Dependencies

### Current Dependencies

- **tokio**: Async runtime
- **serde**: Serialization framework
- **serde_json**: JSON support
- **anyhow**: Error handling
- **thiserror**: Structured error types
- **log**: Logging framework
- **futures**: Async utilities

### Temporarily Removed (Rust version compatibility)

- `rayon` - Parallel data processing (requires Rust 1.80+)
- `config` - Advanced config management (requires Rust 1.80+)
- `tower` / `axum` - HTTP server (to be added later)
- `criterion` - Benchmarking (to be added later)

These will be added back when:
- Rust toolchain is upgraded to 1.80+, or
- Compatible versions are identified

## Migration Notes

### From Python to Rust

The original Python codebase has ~10,000+ lines across multiple modules. The Rust port is being done incrementally:

1. **Core types first** - Error handling, configuration
2. **Analysis engines** - One at a time
3. **Integration** - External tools (Pin, Z3)
4. **API** - HTTP server and workflows
5. **ML** - Hybrid approach (Python + FFI or native Rust)

### Key Differences

**Python:**
```python
def detect_vm(binary):
    try:
        dispatcher = find_dispatcher(binary)
        return VMStructure(dispatcher=dispatcher)
    except VMDetectionError as e:
        logger.error(f"Failed: {e}")
```

**Rust:**
```rust
fn detect_vm(binary: &[u8]) -> Result<VMStructure> {
    let dispatcher = find_dispatcher(binary)?;  // Automatic error propagation
    Ok(VMStructure::new(dispatcher))
}
```

## Troubleshooting

### Build Issues

**Error:** `requires rustc 1.80 or newer`

**Solution:** Upgrade Rust toolchain:
```bash
rustup update stable
```

**Error:** `couldn't find Cargo.toml`

**Solution:** Make sure you're in the `dragonslayer-rs` directory:
```bash
cd dragonslayer-rs
```

### Dependency Conflicts

If you encounter dependency conflicts:
1. Check `Cargo.lock` for pinned versions
2. Run `cargo update` to update dependencies
3. Check Rust version: `rustc --version`

## Next Steps

1. Read `RUST_PORT_PLAN.md` for detailed migration plan
2. Review existing code structure
3. Start implementing VM detection logic
4. Add tests for your implementations
5. Benchmark against Python version

## Contributing

See the main VMDragonSlayer project for contribution guidelines. The Rust port follows:
- MIT-style licensing (as per original project)
- Clear module boundaries
- Comprehensive tests
- Documentation-first approach

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Async Programming in Rust](https://rust-lang.github.io/async-book/)
- Original Python project: `../dragonslayer/`

## Contact

For questions about the Rust port specifically, please create an issue in the repository or contact the maintainers.

