"""
Pattern differential testing utility.

Compares VMDragonSlayer pattern candidates with exports from external tools
(Ghidra, IDA Pro, Binary Ninja) and summarizes overlaps/discrepancies.

Inputs:
- Our candidates JSON (default: artifacts/patterns/ours.json)
- One or more external JSONs in arbitrary simple formats:
  Supported shapes per file:
    - { "<hash>": ["patternA", "patternB", ...], ... }
    - [ {"hash": "...", "patterns": ["...", ...] }, ... ]
    - [ {"hash": "...", "candidates": ["...", ...] }, ... ]

Outputs:
- reports/pattern_diff_summary.md

This script is read-only; it does not execute external tools.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Set, Tuple


@dataclass
class CandidateSet:
    by_hash: Mapping[str, Set[str]]  # hash -> set(pattern IDs/names)
    name: str


def _normalize_patterns(obj: object) -> Set[str]:
    out: Set[str] = set()
    if isinstance(obj, dict):
        # e.g., pattern dicts with 'name' or 'id'
        name = obj.get("name") or obj.get("id") or obj.get("pattern")
        if name is not None:
            out.add(str(name))
    elif isinstance(obj, (list, tuple, set)):
        for x in obj:
            out |= _normalize_patterns(x)
    elif isinstance(obj, str):
        out.add(obj)
    return out


def load_candidates(path: Path, name: str) -> CandidateSet:
    data = json.loads(path.read_text(encoding="utf-8"))
    by_hash: MutableMapping[str, Set[str]] = defaultdict(set)

    if isinstance(data, dict):
        # Case: { hash: [pattern, ...] }
        for h, v in data.items():
            by_hash[str(h)] |= _normalize_patterns(v)
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            h = str(item.get("hash") or item.get("id") or "")
            pats = item.get("patterns") or item.get("candidates") or item.get("matches") or []
            if not pats and "pattern" in item:
                pats = [item["pattern"]]
            by_hash[h] |= _normalize_patterns(pats)
    else:
        # Unknown shape, leave empty
        pass

    # Drop empty hash keys
    by_hash = {k: v for k, v in by_hash.items() if k}
    return CandidateSet(by_hash=by_hash, name=name)


def compare_sets(ours: CandidateSet, externals: List[CandidateSet]) -> str:
    # Collect all hashes
    hashes: Set[str] = set(ours.by_hash.keys())
    for ext in externals:
        hashes |= set(ext.by_hash.keys())

    lines: List[str] = []
    lines.append("# Pattern Differential Testing Summary")
    lines.append("")
    lines.append(f"Our source: {ours.name}")
    if externals:
        lines.append("External sources:")
        for e in externals:
            lines.append(f"- {e.name}")
    lines.append("")

    # Overall stats
    total_hashes = len(hashes)
    lines.append(f"Total unique samples: {total_hashes}")

    # Per-tool overlap metrics
    def jaccard(a: Set[str], b: Set[str]) -> float:
        if not a and not b:
            return 1.0
        u = len(a | b)
        return len(a & b) / u if u else 0.0

    lines.append("")
    lines.append("## Overlap Metrics")
    for e in externals:
        inter = 0
        union = 0
        j_sum = 0.0
        compared = 0
        for h in hashes:
            a = ours.by_hash.get(h, set())
            b = e.by_hash.get(h, set())
            if a or b:
                inter += len(a & b)
                union += len(a | b)
                j_sum += jaccard(a, b)
                compared += 1
        jac_overall = (inter / union) if union else 1.0
        jac_avg = (j_sum / compared) if compared else 1.0
        lines.append(f"- {e.name}: Jaccard-overall={jac_overall:.3f}, Jaccard-avg={jac_avg:.3f}")

    # Discrepancy samples
    lines.append("")
    lines.append("## Discrepancies (by sample)")
    for e in externals:
        diffs = []
        for h in sorted(hashes):
            a = ours.by_hash.get(h, set())
            b = e.by_hash.get(h, set())
            only_ours = sorted(a - b)
            only_ext = sorted(b - a)
            if only_ours or only_ext:
                diffs.append((h, only_ours, only_ext))
        lines.append("")
        lines.append(f"### vs {e.name}")
        if not diffs:
            lines.append("No discrepancies; all candidate sets identical for compared samples.")
            continue
        lines.append("hash | only_ours | only_external")
        lines.append("--- | --- | ---")
        for h, oo, oe in diffs[:200]:  # cap to keep summary readable
            oo_s = ", ".join(oo) if oo else "-"
            oe_s = ", ".join(oe) if oe else "-"
            lines.append(f"{h} | {oo_s} | {oe_s}")
        if len(diffs) > 200:
            lines.append(f"... and {len(diffs) - 200} more rows truncated ...")

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Differential testing of pattern candidates")
    ap.add_argument(
        "--ours",
        type=Path,
        default=Path("artifacts/patterns/ours.json"),
        help="Path to our candidates JSON",
    )
    ap.add_argument(
        "--external",
        action="append",
        default=[],
        help="External source in the form name=path/to/file.json (repeatable)",
    )
    ap.add_argument(
        "--reports-dir",
        type=Path,
        default=Path("reports"),
        help="Directory to write the summary markdown",
    )
    args = ap.parse_args()

    ours = load_candidates(args.ours, name="ours")
    externals: List[CandidateSet] = []
    for item in args.external:
        if not isinstance(item, str) or "=" not in item:
            continue
        name, _, p = item.partition("=")
        ext_path = Path(p)
        if ext_path.exists():
            externals.append(load_candidates(ext_path, name=name))

    summary = compare_sets(ours, externals)
    args.reports_dir.mkdir(parents=True, exist_ok=True)
    out = args.reports_dir / "pattern_diff_summary.md"
    out.write_text(summary, encoding="utf-8")
    print(f"Wrote differential testing summary to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
