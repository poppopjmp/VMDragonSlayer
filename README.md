# VMDragonSlayer
Automated multi-engine framework for unpacking, analyzing, and devirtualizing binaries protected by commercial and custom Virtual Machine (VM) based protectors (e.g., VMProtect 2.x/3.x, Themida) and bespoke malware VMs. Combines Dynamic Taint Tracking (DTT), Symbolic Execution (SE), Pattern & Semantic Classification, and Machine Learning–driven prioritization to dramatically reduce manual reverse engineering time.

> Goal: Turn weeks/months of protected binary analysis into minutes/hours of structured, explainable semantic output.

---
## Core Capabilities
| Domain | Engine / Module | Highlights |
|--------|-----------------|-----------|
| VM Discovery | `analysis.vm_discovery` | Dispatcher & handler table identification, nested VM heuristics |
| Pattern Analysis | `analysis.pattern_analysis` | Rule-based + similarity + ML (hybrid auto-selection) |
| Taint Tracking | `analysis.taint_tracking` | Intel Pin–driven byte-level taint, handler discovery, flow confidence |
| Symbolic Execution | `analysis.symbolic_execution.executor` | PathPrioritizer ML-weighted exploration, constraint & state tracking |
| Hybrid Orchestration | (Python core) | Sequential / parallel / adaptive workflows (Ghidra report indicates implemented) |
| Synthetic Data | `data/training/synthetic_sample_generator.py` | Obfuscation mutation, multi-architecture sample generation |
| Pattern DB | `data/patterns/` | JSON + enhanced DB + SQLite-backed runtime patterns |
| Ghidra Plugin | `plugins/ghidra/` | In-progress UI integration (several templates missing) |
| Schemas / Validation | `data/schemas/` | JSON schema–validated analysis output & pattern formats |

---
## Architecture (High-Level)
```
┌─────────────────────────────────────────────────────────┐
│                     VMDragonSlayer                      │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐ │
│  │ VM Discovery │-→ │ Pattern/ML   │-→ │ Semantic SE  │ │
│  └──────────────┘   └──────────────┘   └──────────────┘ │
│          ↑                   │                 │        │
│          │             ┌──────────┐            │        │
│          │             │ Taint    │────────────┘        │
│          │             │ Tracking │ (handler seeds)     │
│          │             └──────────┘                     │
│          │                    │                         │
│     ┌───────────────┐   ┌───────────────┐               │
│     │ Pattern DB /  │   │ Path Priorit. │               │
│     │  SQLite JSON  │   │ (ML weights)  │               │
│     └───────────────┘   └───────────────┘               │
│                │                │                       │
│           ┌─────────── Orchestrator ───────────┐        │
│           │ Sequential / Parallel / Adaptive   │        │
│           └────────────────────────────────────┘        │
│                 │                 │                     │
│         ┌────────────┐    ┌────────────┐                │
│         │ API (REST) │    │  Plugins   │ (Ghidra, etc.) │
│         └────────────┘    └────────────┘                │
└─────────────────────────────────────────────────────────┘
```

---
## Repository Layout (Relevant Extract)
```
VMDragonSlayer-private/
├── dragonslayer/
│   ├── analysis/
│   │   ├── vm_discovery/
│   │   ├── pattern_analysis/
│   │   ├── symbolic_execution/
│   │   ├── taint_tracking/
│   │   └── anti_evasion/
│   ├── api/
│   ├── core/            # (pyc present; sources may be trimmed/migrated)
│   ├── ml/
│   ├── analytics/
│   ├── enterprise/
│   ├── gpu/             # (GPU infra placeholder)
│   └── utils/
├── data/
│   ├── patterns/
│   ├── models/
│   ├── samples/
│   ├── training/
│   ├── schemas/
│   ├── taint_config.properties
│   └── database_config.json
├── plugins/
│   └── ghidra/          # Java integration (partial)
└── README.md (this file)
```

---
## Core Analysis Engines
### 1. VM Discovery (`analysis/vm_discovery`)
Heuristics for:
- Dispatcher loop detection (`loop_threshold`, tainted read density)
- Handler table region clustering (address/stride patterns)
- Nested VM detection (`vm.detect_nested_vms=true`)

### 2. Dynamic Taint Tracking (`analysis/taint_tracking`)
Configuration surfaced in `data/taint_config.properties`:
- Byte-level precision (`taint.precision=byte_level`)
- Shadow memory tagging
- Control / data flow influence flags
- Anti-analysis bypass (e.g., `antianalysis.spoof_rdtsc=true`, `hide_debugger=true`)
- Pattern regex classification (e.g., `pattern.vm_xor`, `pattern.vm_jmp`)

### 3. Pattern Analysis (`analysis/pattern_analysis`)
Implements multi-layer classification pipeline:
- Rule-based recognizer (signature / structural features)
- Similarity engine (approximate / fuzzy matching)
- ML classifier (scikit-learn RandomForest + feature extraction)
- Hybrid / AUTO mode merges confidence + fallback ordering

### 4. Symbolic Execution (`analysis/symbolic_execution/executor.py`)
Features:
- `ExecutionContext` tracking registers, symbolic memory, constraints
- `SymbolicValue` & `SymbolicConstraint` models (type taxonomy: arithmetic, bitwise, memory, boolean)
- `PathPrioritizer` uses weighted VM pattern signals: dispatcher access, handler entry, anti-analysis checks, stack manipulation
- Branch exploration w/ depth limit, novelty scoring, constraint diversity weighting
- Timeout & max path controls (configurable)

### 5. Hybrid Orchestrator (Documented in reports)
Workflow strategies (per fix report):
- `sequential` / `parallel` / `adaptive` / `optimized`
Chained phases:
1. VM Discovery → 2. Pattern Recognition → 3. Taint Tracking → 4. SE → 5. Hybrid / Batch

---
## Synthetic Sample Generation
`data/training/synthetic_sample_generator.py` provides:
- `PatternMutator`: register & instruction substitution, junk insertion, polymorphic pattern shaping
- `VMInstructionGenerator`: Weighted opcode distributions, multi-architecture emitters:
  - VMProtect 2.x (variable-length + stack frame references)
  - VMProtect 3.x (alternate register patterns)
  - Themida (indirect addressing + trampolines)
  - Generic fallback
Use cases:
- Augment sparse real-world datasets
- Stress-test pattern generalization
- Populate ML training with controlled mutation depth

---
## Pattern Database
Locations:
- `data/patterns/pattern_database.json`
- `data/patterns/pattern_database_enhanced.json`
Capabilities:
- Categories: arithmetic, obfuscation (MBA, register renaming, instruction substitution), control-flow, structural, handler signatures
- Fields: `id`, `name`, `type`, `confidence`, `handler_patterns` (regex), `indicators`, `frequency`
- Supports similarity scoring + multi-match aggregation

### Example Entry (abridged):
```json
{
  "id": "instruction_substitution",
  "type": "obfuscation",
  "confidence": 0.71,
  "handler_patterns": ["\\x8B\\x45\\xFC..."],
  "indicators": ["double_negation", "complex_equivalent"]
}
```

---
## Taint Configuration Highlights (`data/taint_config.properties`)
| Category | Key Examples |
|----------|--------------|
| Precision | `taint.precision=byte_level`, `taint.memory_tagging=shadow_memory` |
| VM Heuristics | `vm.handler.clustering_threshold=0.8`, `vm.detect_polymorphic_handlers=true` |
| Anti-Analysis | `antianalysis.spoof_rdtsc=true`, `antianalysis.hide_debugger=true` |
| Symbolic Link | `symbolic.solver=z3`, `symbolic.path_pruning=true` |
| ML Integration | `ml.enable_pattern_recognition=true`, `ml.feature_extraction=ngram_opcodes` |
| Pattern Regex | `pattern.vm_add=.*add|sum.*`, `pattern.vm_jmp=.*jmp|jump|goto.*` |
| Output | JSON enriched flows, CFG, handler graph inclusion |

---
## Machine Learning Pipeline
Components:
- Feature extraction (opcode counts, structural entropy, taint-propagation metrics, symbolic depth)
- RandomForest baseline classifier (confidence gating)
- Similarity fallback for sparse classes
- Rule-based early-exit for high-confidence known signatures
- Planned: Transformer-based handler embeddings (per roadmap material)

Training Data Organization:
```
training/
  bytecode_classification/
  vm_detection/
  handler_classification/
```
Synthetic augmentation ensures class balance & mutation resilience.

---
## API & Plugin Integration
Although not all source stubs are present in this snapshot, documentation & reports show:
- REST API (FastAPI implied) for remote orchestration
- Engine status modeling (`EngineStatus.java`) for plugin heartbeat


Planned / Documented features:
- Real-time annotation of handlers
- Automated function renaming w/ semantic ops
- Batch submission & progress polling

---
## Quick Start (Conceptual)
> NOTE: Exact dependency list not fully present; adapt below to your environment.

### 1. Clone & Environment
```bash
python -m venv venv
source venv/bin/activate  # (Linux/macOS)
# or
venv\Scripts\activate    # (Windows)

pip install --upgrade pip
# Core probable deps (adjust as needed):
pip install angr z3-solver capstone unicorn keystone-engine
pip install scikit-learn numpy scipy joblib
pip install fastapi uvicorn[standard]
```

### 2. Configure Data & Env
```bash
cp data/.env.template .env
# Edit Pin path, model paths, DB URIs, etc.
```

### 3. Run (Hypothetical Examples)
```bash
# Start API (if implemented)
uvicorn dragonslayer.api.server:app --reload

# Programmatic
python -c "from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor; print('Initialized')"
```

### 4. Integrate Ghidra (WIP)
- Build plugin under `plugins/ghidra/`
- Configure endpoint + API token in Ghidra tool options

---
## 🧪 Usage (Illustrative)
```python
from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor, ExecutionContext, SymbolicValue

# Initialize executor (using default config object fallback)
executor = SymbolicExecutor()

# Seed minimal context
ctx = ExecutionContext(
    pc=0x401000,
    registers={'R0': SymbolicValue('R0_input', is_input=True)},
    path_id="seed_path",
    depth=0
)

# Execute (with default step model)
import asyncio
result = asyncio.run(executor.execute(ctx, instruction_handler=None))
print(result.to_dict())
```

---
## Extensibility
### Add New Pattern
1. Extend `pattern_database_enhanced.json` with entry (set provisional confidence)
2. Re-run pattern loader / warm similarity index
3. (Optional) Provide training examples mapped to new semantic label

### Add Instruction Mutations
- Edit `PatternMutator` maps (register & equivalent instruction dictionaries)
- Increase variant coverage for resilient classifier training

### Plug Custom Solver
- Replace default step handler via `instruction_handler` coroutine returning forked `ExecutionContext` list

---
## Performance Tips
| Scenario | Recommendation |
|----------|---------------|
| Large path explosion | Lower `symbolic_execution_max_depth`; enable pruning | 
| Slow taint throughput | Disable `detailed_taint_flows`; reduce threads if thrashing |
| High false positives (handlers) | Raise clustering threshold (`vm.handler.clustering_threshold`) |
| Overfitting patterns | Introduce mutated synthetic variants; drop high-frequency duplicates |
| Memory pressure | Reduce `performance.max_threads`; enable result caching TTL |

---
## Security & Sandbox Guidelines
- Always analyze untrusted samples inside isolated VM w/ no network (or controlled redirect)
- Disable hardware acceleration in hostile virtualized guest if anti-analysis escalation suspected
- Treat generated intermediate artifacts (lifted code, temp dumps) as sensitive
- Rotate API keys & purge caches containing classified semantic outputs periodically

---
## ⚠ Known Limitations (Observed / Reported)
| Area | Constraint |
|------|-----------|
| Highly metamorphic handlers | Pattern generalization still under development |
| Deeply nested (>5) VM layers | Exponential state explosion risk |
| Self-modifying dispatchers | Partial adaptation; may require dynamic rewrite logging |
| Quantum / post-quantum obfuscation | Not supported (research placeholder) |
| GPU acceleration | Skeleton only (gpu/ directory placeholder) |
| Ghidra exporter / FS modules | Missing implementations (templates) |

---
## Roadmap (From Internal Docs / Slides)
| Phase | Focus |
|-------|-------|
| Q3-Q4 2025 | Transformer-based handler model, CUDA SE acceleration, distributed orchestration |
| 2026 | Full deobfuscation pipeline (clean code reconstruction), advanced Ghidra automation, anomaly-based zero-day VM detection |

Planned Research: Adversarial ML hardening, distributed GPU symbolic solving, pattern generalization for metamorphic handlers.

---
## Contributing
1. Fork repository
2. Create feature branch (`feat/<module>-improvement`)
3. Add tests / synthetic samples if ML-impacting
4. Validate JSON against schemas in `data/schemas/`
5. Submit PR referencing issue / enhancement proposal

Please do **NOT** submit real malware binaries—use hashes + metadata or synthetic reproductions.

---
## License
See `LICENSE` (not reproduced here). Ensure compliance when redistributing pattern databases or third-party model weights.

---
## Citation / Attribution (Suggested)
```
@software{vmdragonslayer_2025,
  title   = {VMDragonSlayer: Automated Devirtualization & Semantic VM Handler Analysis},
  author  = {Panico, Agostino},
  year    = {2025},
  url     = {https://github.com/poppopjmp/VMDragonSlayer}
}
```

---
## Support & Questions
- Issues: GitHub issue tracker
- Research / collaboration: van1sh@securitybsides.it

---
## At a Glance
| Metric | Benefit |
|--------|---------|
| Coverage vs manual | 3–10× semantic yield (reported) |
| Time reduction | Weeks → Minutes/Hours |
| Failure modes | Metamorphic / nested VMs, extreme anti-analysis |
| Extensibility | JSON + Python + ML modular stack |

> *Every dragon leaves traces: taint the bytecode, follow the handlers, decode the semantics.*
