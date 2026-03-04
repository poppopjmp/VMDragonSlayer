import json
import sys
from pathlib import Path


def main():
    report = Path("evidence/bandit.xml")
    if not report.exists():
        print("bandit.xml not found", file=sys.stderr)
        return 1
    # Cheap parse: fail only if HIGH or CRITICAL severities appear
    text = report.read_text(encoding="utf-8", errors="ignore").lower()
    fail = ("severity=\"high\"" in text) or ("severity=\"critical\"" in text)
    print("bandit_gate:", "FAIL" if fail else "PASS")
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
