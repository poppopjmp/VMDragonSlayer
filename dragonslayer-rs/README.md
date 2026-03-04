# DragonSlayer-RS

Rust port of VMDragonSlayer - an automated multi-engine framework for unpacking, analyzing, and devirtualizing binaries.

## Project Status

🚧 **Planning Phase**

This is the Rust port of the VMDragonSlayer Python framework. The migration is a work-in-progress with comprehensive planning documented in `RUST_PORT_PLAN.md`.

## Overview

VMDragonSlayer is a comprehensive framework for analyzing binaries protected by Virtual Machine (VM) based protectors such as VMProtect 2.x/3.x, Themida, and custom malware VMs. The framework combines multiple analysis engines including Dynamic Taint Tracking (DTT), Symbolic Execution (SE), Pattern Classification, and Machine Learning.

### Key Features

- **Multi-Engine Analysis**: Static, dynamic, and hybrid analysis techniques
- **VM Detection**: Automated detection of commercial and custom VM protectors
- **High Performance**: Expected 5-10x performance improvement over Python version
- **Memory Safety**: Rust's ownership system prevents entire classes of bugs
- **True Concurrency**: Multi-threaded async runtime with safe parallel execution

## Architecture

```
dragonslayer-rs/
├── src/
│   ├── core/              # Core infrastructure
│   │   ├── config.rs      # Configuration management
│   │   ├── orchestrator.rs # Workflow coordination
│   │   └── error.rs       # Error handling
│   ├── analysis/          # Analysis engines
│   │   ├── vm_discovery/  # VM detection and classification
│   │   ├── pattern_analysis/ # Pattern matching and classification
│   │   ├── taint_tracking/ # Dynamic taint analysis (FFI to Pin)
│   │   └── symbolic_execution/ # Symbolic execution (Z3)
│   ├── api/               # HTTP API (Axum)
│   ├── ml/                # Machine learning (hybrid Python/Rust)
│   ├── workflows/         # Workflow management
│   └── utils/             # Utility functions
├── Cargo.toml
└── RUST_PORT_PLAN.md      # Comprehensive migration plan
```

## Building

```bash
# Build the project
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## Development Phases

### Phase 1: Foundation (Weeks 1-4) - IN PROGRESS
- [x] Project structure setup
- [x] Configuration system
- [ ] Core error types
- [ ] Basic orchestrator
- [ ] Logging setup
- [ ] Unit tests

### Phase 2: Analysis Engines Part 1 (Weeks 5-12)
- [ ] VM Discovery engine
- [ ] Pattern Analysis engine
- [ ] Integration tests

### Phase 3: External Tool Integration (Weeks 13-20)
- [ ] Intel Pin FFI wrapper
- [ ] Taint tracking adapter
- [ ] Z3 integration
- [ ] Symbolic execution engine

### Phase 4: API and Workflows (Weeks 21-25)
- [ ] Axum API server
- [ ] Workflow management
- [ ] WebSocket support

### Phase 5: ML Integration (Weeks 26-32)
- [ ] Hybrid ML system
- [ ] Model loading and inference
- [ ] Feature extraction

### Phase 6: Polish and Optimization (Weeks 33-38)
- [ ] Performance optimization
- [ ] Test coverage >80%
- [ ] Documentation
- [ ] Production deployment

## Technology Stack

- **Runtime**: Tokio (async runtime)
- **HTTP**: Axum
- **Serialization**: Serde
- **Error Handling**: Anyhow + Thiserror
- **Logging**: Tracing
- **Binary Analysis**: object, pelite, goblin
- **ML**: Hybrid approach with PyO3 or Candle
- **Symbolic Execution**: Z3 via FFI
- **Dynamic Analysis**: Intel Pin (C++ FFI)

## Performance Targets

| Component | Python | Rust (Target) | Improvement |
|-----------|--------|---------------|-------------|
| VM Detection | 5-10s | 1-2s | **5-10x faster** |
| Pattern Matching | 3-5s | 0.5-1s | **5-10x faster** |
| API Latency | 200-500ms | 50-100ms | **4-5x faster** |
| Memory Usage | 500MB-1GB | 100-200MB | **5x reduction** |
| Concurrent Requests | 20-50 | 200-500 | **10x improvement** |

## Documentation

- **Migration Plan**: See `RUST_PORT_PLAN.md` for comprehensive details
- **Original Python Project**: See parent directory `../`
- **API Documentation**: `cargo doc --open`

## Contributing

This is a work-in-progress port. For now, focus on:

1. Reading the migration plan
2. Implementing Phase 1 foundation
3. Setting up CI/CD
4. Writing tests

## License

GPL-3.0-or-later (same as VMDragonSlayer)

## Related Projects

- Original Python version: `../dragonslayer/`
- Python Plugin Integrations: `../plugins/`

