import sys
from pathlib import Path
import xml.etree.ElementTree as ET


VALIDATION_SCOPES = (
    # Forms when coverage.xml filenames are relative to project root
    "dragonslayer/core/",
    "dragonslayer/analysis/vm_discovery/",
    "dragonslayer/analysis/pattern_analysis/",
    # Forms when coverage.xml uses <source> dragonslayer and filenames are relative to it
    "core/",
    "analysis/vm_discovery/",
    "analysis/pattern_analysis/",
)


def _normalize(path: str) -> str:
    return path.replace("\\", "/")


def parse_coverage_scoped(xml_path: Path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Accumulators for validated scope
    scope_lines_total = 0
    scope_lines_covered = 0

    # Accumulators for core branch coverage
    core_branch_num = 0.0
    core_branch_den = 0.0

    for pkg in root.findall("./packages/package"):
        for cls in pkg.findall("classes/class"):
            filename = _normalize(cls.attrib.get("filename", ""))
            in_scope = filename.startswith(VALIDATION_SCOPES)
            in_core = filename.startswith(("dragonslayer/core/", "core/"))

            # Derive line counts from <line hits> when available
            lines = cls.findall("lines/line")
            if lines:
                total = len(lines)
                covered = sum(1 for ln in lines if int(ln.attrib.get("hits", "0")) > 0)
            else:
                # Fallback to attributes (Cobertura extension)
                total = int(cls.attrib.get("lines-valid", "0"))
                covered = int(cls.attrib.get("lines-covered", "0"))
                # As a last resort, approximate using line-rate
                if total == 0:
                    lr = float(cls.attrib.get("line-rate", 0.0))
                    total = 1
                    covered = lr >= 1.0

            if in_scope:
                scope_lines_total += total
                scope_lines_covered += covered

            # Branch coverage for core: try branches attributes, else branch-rate weighted by lines
            if in_core:
                bv = cls.attrib.get("branches-valid")
                bc = cls.attrib.get("branches-covered")
                if bv is not None and bc is not None:
                    core_branch_den += float(bv)
                    core_branch_num += float(bc)
                else:
                    br = float(cls.attrib.get("branch-rate", 0.0))
                    core_branch_den += float(total)
                    core_branch_num += br * float(total)

    scope_line_rate = (scope_lines_covered / scope_lines_total) if scope_lines_total else 0.0
    core_branch_rate = (core_branch_num / core_branch_den) if core_branch_den else 0.0

    return scope_line_rate, core_branch_rate


def main():
    xml_path = Path("evidence/coverage.xml")
    if not xml_path.exists():
        print("coverage.xml not found", file=sys.stderr)
        return 1

    scope_line_rate, core_branch_rate = parse_coverage_scoped(xml_path)

    # Gates
    ok_line = scope_line_rate >= 0.85
    ok_core = core_branch_rate >= 0.90

    print(
        f"validated_scope_line_rate={scope_line_rate:.3f} core_branch_rate={core_branch_rate:.3f}"
    )
    if not ok_line:
        print(
            f"FAIL: validated scope line coverage {scope_line_rate:.3f} < 0.85",
            file=sys.stderr,
        )
    if not ok_core:
        print(
            f"FAIL: core branch coverage {core_branch_rate:.3f} < 0.90",
            file=sys.stderr,
        )
    return 0 if (ok_line and ok_core) else 1


if __name__ == "__main__":
    raise SystemExit(main())
