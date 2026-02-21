# Glossary

Key terms used in VMDragonSlayer.

## VM Protection Concepts

| Term | Definition |
|------|------------|
| **Virtual Machine (VM) Protection** | Software protection technique that converts native x86/x64 instructions into bytecode for a custom virtual machine, making reverse engineering harder. |
| **vIP (Virtual Instruction Pointer)** | The register (or memory location) inside the VM that points to the current bytecode instruction. Typically a native register (ESI, EDI, EBX) repurposed as the VM's program counter. |
| **Handler** | A native code snippet that implements one VM opcode. The dispatcher jumps to handlers to execute each bytecode instruction. |
| **Dispatcher** | The central loop of the VM that fetches the next bytecode opcode, decodes it, and transfers control to the corresponding handler. |
| **Handler Table** | A lookup table (array or switch/case) mapping bytecode opcodes to handler addresses. |
| **Devirtualisation (Devirt)** | The process of recovering the original native instructions from a VM-protected binary by analysing handlers, bytecode, and dispatch logic. |
| **Bytecode** | The custom instruction set that a VM protector generates from the original native code. Each VM protector has a unique bytecode format. |

## Protectors

| Term | Definition |
|------|------------|
| **VMProtect** | Commercial binary protector supporting code virtualisation, mutation, and packing. Uses a stack-based VM with indirect dispatch via handler tables. |
| **Themida / WinLicense** | Commercial protector by Oreans. Uses EDI-based context structure, ESI as vIP, pushad/popad prologues, and [edi+offset] memory-mapped virtual registers. |
| **Code Virtualizer** | Another Oreans product. Uses LODSB/XLAT fetch-decrypt cycles, ESP-based context, BSWAP data transformations, and LODSD for wide operand fetches. |

## Analysis Techniques

| Term | Definition |
|------|------------|
| **Taint Tracking** | Data-flow analysis technique that marks ("taints") data from untrusted sources and propagates taint through operations to detect how data flows to sensitive sinks. |
| **Symbolic Execution** | Execution of a program with symbolic (variable) inputs instead of concrete values, building logical constraints over execution paths that can be solved with an SMT solver (z3). |
| **MBA (Mixed Boolean-Arithmetic)** | Expressions combining arithmetic (+, −, ×) and bitwise (AND, OR, XOR, NOT) operations. Used by protectors to obfuscate constants and expressions. MBA simplification recovers the original expression. |
| **Opaque Predicate** | A conditional branch whose outcome is always the same (always-true or always-false) but is difficult to determine statically. Used by protectors to add fake control-flow paths. |
| **CFG (Control Flow Graph)** | A directed graph where nodes are basic blocks (straight-line instruction sequences) and edges represent branches, jumps, or fall-through transitions. |
| **SSA (Static Single Assignment)** | An intermediate representation where every variable is assigned exactly once. DragonSlayer uses SSA form for pseudocode emission. |

## Data Structures

| Term | Definition |
|------|------------|
| **ExecutionTrace** | The primary data structure representing a recorded execution: a sequence of `TraceInstruction` records plus handler markers, memory accesses, control-flow events, and metadata. |
| **TraceInstruction** | A single instruction observed during trace collection: address, mnemonic, operands, register state, and taint info. |
| **HandlerMarker** | Annotation marking where in the trace a VM handler begins, including handler ID, address, and classified handler type. |
| **CollectionResult** | Output of `collect_trace()`: wraps an `ExecutionTrace` with backend info, elapsed time, and truncation status. |
| **AnalysisResult** | The top-level result from `Orchestrator.analyze_binary()`: contains results from every enabled analysis engine plus metadata and metrics. |

## Machine Learning

| Term | Definition |
|------|------------|
| **Handler Classifier** | ML model (GradientBoosting or RandomForest) trained to classify VM handler code sequences into one of 12 canonical categories (arithmetic, bitwise, memory, stack, control_flow, etc.). |
| **Feature Vector** | A 132-element numeric vector extracted from a handler's instruction sequence: mnemonic frequencies, register patterns, memory access ratios, control-flow features, statistical features, and interaction terms. |
| **Synthetic Data** | Training data generated from handler templates with jitter transforms (NOP insertion, register renaming, dead-code injection) to simulate realistic handler variation. |

## Infrastructure

| Term | Definition |
|------|------------|
| **Orchestrator** | The central coordinator (`dragonslayer.core.orchestrator.Orchestrator`) that accepts analysis requests, selects strategies, dispatches to engines, and aggregates results. |
| **Pipeline** | A multi-stage processing chain (`dragonslayer.core.pipeline`) with per-stage timeouts, error handling, and `avg_confidence` aggregation. |
| **Trace Backend** | The execution engine used to collect a trace: Unicorn (built-in), Triton, angr, Qiling, or file-based import. |
| **Output Format** | Trace export target: JSON (full-fidelity), TEXT (FORMAT.md), CSV (tabular), IDA (annotation JSON), Ghidra (Jython script). |
