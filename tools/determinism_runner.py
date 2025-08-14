import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

import numpy as np

from dragonslayer.core.orchestrator import Orchestrator, AnalysisRequest, AnalysisType


def run_once(data: bytes, analysis: str) -> Dict[str, Any]:
    orch = Orchestrator()
    req = AnalysisRequest(binary_data=data, analysis_type=AnalysisType(analysis))
    res = __import__("asyncio").run(orch.execute_analysis(req))
    return {
        "success": res.success,
        "results": res.results,
        "errors": res.errors,
        "warnings": res.warnings,
    }


def normalize(obj: Any) -> Any:
    # Remove non-deterministic fields like timestamps
    if isinstance(obj, dict):
        return {k: normalize(v) for k, v in obj.items() if k not in {"timestamp"}}
    if isinstance(obj, list):
        return [normalize(v) for v in obj]
    return obj


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis", default="vm_discovery")
    ap.add_argument("--size", type=int, default=1024)
    ap.add_argument("--seed", type=int, default=123)
    ap.add_argument("--out", default="evidence/determinism_report.json")
    args = ap.parse_args(argv)

    rng = np.random.default_rng(args.seed)
    data = rng.integers(0, 256, size=args.size, dtype=np.uint8).tobytes()

    outputs = []
    for _ in range(3):
        outputs.append(normalize(run_once(data, args.analysis)))

    digests = [hashlib.sha256(json.dumps(o, sort_keys=True).encode()).hexdigest() for o in outputs]
    identical = len(set(digests)) == 1

    report = {"identical": identical, "digests": digests}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))
    return 0 if identical else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
