import argparse
import json
import os
from pathlib import Path
from typing import List

PATTERNS = [
    "configs/*.yml",
    "logs/**/*.log",
    "reports/**/*",
    "artifacts/**/*",
    "evidence/coverage.xml",
    "evidence/ruff.xml",
    "evidence/mypy.xml",
    "evidence/bandit.xml",
    "evidence/pip_audit.json",
    "evidence/determinism_report.json",
]


def glob_many(patterns: List[str]) -> List[Path]:
    out: List[Path] = []
    for pat in patterns:
        out.extend(Path().glob(pat))
    return [p for p in out if p.exists()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="evidence")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write basic env info
    (out_dir / "ENVIRONMENT.txt").write_text(
        f"PYTHONHASHSEED={os.environ.get('PYTHONHASHSEED','')}\n",
        encoding="utf-8",
    )

    files = glob_many(PATTERNS)
    manifest = {"files": [str(p) for p in files]}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Collected {len(files)} evidence files")


if __name__ == "__main__":
    main()
