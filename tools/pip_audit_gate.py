import json
from pathlib import Path
import sys


def main():
    path = Path("evidence/pip_audit.json")
    if not path.exists():
        print("pip_audit.json not found", file=sys.stderr)
        return 1
    data = json.loads(path.read_text(encoding="utf-8"))
    # Data can be list of {name,version,vulns:[{id,fix_versions,advisory:{severity}}]}
    high_or_critical = []
    for pkg in data if isinstance(data, list) else []:
        for v in pkg.get("vulns", []) or []:
            sev = (v.get("advisory", {}) or {}).get("severity") or ""
            if str(sev).upper() in {"HIGH", "CRITICAL"}:
                high_or_critical.append({"pkg": pkg.get("name"), "id": v.get("id"), "severity": sev})
    print(f"pip-audit gate: {len(high_or_critical)} high/critical vulns")
    return 0 if not high_or_critical else 1


if __name__ == "__main__":
    raise SystemExit(main())
