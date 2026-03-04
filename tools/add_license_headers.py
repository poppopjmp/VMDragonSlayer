"""
Insert GPL license header comment into Python files.

Rules:
- Read canonical header from LICENSE-HEADER.txt.
- Insert as comment block after any shebang, before module docstring/code.
- Preserve existing shebang line.
- Skip files that already contain the header marker.
- Target folders: dragonslayer/** and plugins/** by default.
- Skip tests/** unless --include-tests is provided.

Usage:
    python tools/add_license_headers.py --apply [--include-tests]
    python tools/add_license_headers.py --check
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HEADER_FILE = REPO_ROOT / "LICENSE-HEADER.txt"
HEADER_MARKER = "VMDragonSlayer - Advanced VM detection and analysis library"


def load_header_as_comment() -> list[str]:
    text = HEADER_FILE.read_text(encoding="utf-8")
    # Strip leading/trailing triple quotes if present
    stripped = text.strip()
    if stripped.startswith('"""') and stripped.endswith('"""'):
        stripped = stripped[3:-3].strip("\n\r ")
    elif stripped.startswith("'''") and stripped.endswith("'''"):
        stripped = stripped[3:-3].strip("\n\r ")

    lines = []
    for line in stripped.splitlines():
        if line.strip() == "":
            lines.append("#")
        else:
            lines.append(f"# {line.rstrip()}")
    return lines


def load_header_as_java_block() -> str:
    text = HEADER_FILE.read_text(encoding="utf-8")
    stripped = text.strip()
    if stripped.startswith('"""') and stripped.endswith('"""'):
        stripped = stripped[3:-3].strip("\n\r ")
    elif stripped.startswith("'''") and stripped.endswith("'''"):
        stripped = stripped[3:-3].strip("\n\r ")

    body_lines = [line.rstrip() for line in stripped.splitlines()]
    block = ["/*"]
    for line in body_lines:
        if line.strip() == "":
            block.append(" *")
        else:
            block.append(f" * {line}")
    block.append(" */")
    return "\n".join(block)


def should_process(path: Path, include_tests: bool) -> bool:
    if not path.suffix == ".py":
        return False
    # Only process dragonslayer/** and plugins/**
    try:
        rel = path.relative_to(REPO_ROOT)
    except ValueError:
        return False

    parts = rel.parts
    if not parts:
        return False
    top = parts[0]
    allowed_tops = {"dragonslayer", "plugins"}
    if include_tests:
        allowed_tops.add("tests")
    if top not in allowed_tops:
        return False
    # Skip this tool itself
    if rel.as_posix().startswith("tools/"):
        return False
    # Skip virtual envs or build outputs if any
    if any(p in {".venv", "venv", "build", "dist", "__pycache__"} for p in parts):
        return False
    return True


def find_python_files(include_tests: bool) -> Iterable[Path]:
    tops = [REPO_ROOT / "dragonslayer", REPO_ROOT / "plugins"]
    if include_tests:
        tops.append(REPO_ROOT / "tests")
    for top in tops:
        if not top.exists():
            continue
        for root, dirs, files in os.walk(top):
            # Prune unwanted dirs
            dirs[:] = [
                d
                for d in dirs
                if d not in {".venv", "venv", "__pycache__", "build", "dist"}
            ]
            if not include_tests and "tests" in dirs:
                # still walk, but skip the tests subtree
                pass
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                path = Path(root) / fname
                if should_process(path, include_tests):
                    yield path


def has_header(content: str) -> bool:
    # Check in first ~50 lines
    head = "\n".join(content.splitlines()[:50])
    return HEADER_MARKER in head


def insert_header(content: str, header_lines: list[str]) -> tuple[str, bool]:
    if has_header(content):
        return content, False

    lines = content.splitlines()
    new_lines: list[str] = []

    idx = 0
    # Preserve shebang if present
    if lines and lines[0].startswith("#!"):
        new_lines.append(lines[0])
        idx = 1

    # Insert header comment
    new_lines.extend(header_lines)
    new_lines.append("")  # blank line after header

    # Append the rest of the file
    new_lines.extend(lines[idx:])

    # Preserve trailing newline if original had it
    new_content = "\n".join(new_lines)
    if content.endswith("\n") and not new_content.endswith("\n"):
        new_content += "\n"
    return new_content, True


def insert_java_header(content: str, header_block: str) -> tuple[str, bool]:
    # If header marker present near top, skip
    head = "\n".join(content.splitlines()[:80])
    if HEADER_MARKER in head:
        return content, False

    lines = content.splitlines()
    # If file starts with Unicode BOM chars, keep them
    if lines and lines[0].startswith("\ufeff"):
        # Keep BOM on its own line
        bom = lines[0]
        new_content = "\n".join([bom, header_block, ""] + lines[1:])
        if content.endswith("\n") and not new_content.endswith("\n"):
            new_content += "\n"
        return new_content, True

    # Insert header at top (before package/import)
    new_content = "\n".join([header_block, ""] + lines)
    if content.endswith("\n") and not new_content.endswith("\n"):
        new_content += "\n"
    return new_content, True


def process_file(path: Path, header_lines: list[str], apply: bool) -> bool:
    original = path.read_text(encoding="utf-8")
    updated, changed = insert_header(original, header_lines)
    if changed and apply:
        path.write_text(updated, encoding="utf-8")
    return changed


def process_java_file(path: Path, header_block: str, apply: bool) -> bool:
    original = path.read_text(encoding="utf-8")
    updated, changed = insert_java_header(original, header_block)
    if changed and apply:
        path.write_text(updated, encoding="utf-8")
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add GPL header comments to Python files"
    )
    parser.add_argument(
        "--apply", action="store_true", help="Apply changes (otherwise dry-run)"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if any file is missing a header",
    )
    parser.add_argument(
        "--include-tests", action="store_true", help="Also add headers to tests/"
    )
    args = parser.parse_args()

    header_lines = load_header_as_comment()
    header_java = load_header_as_java_block()

    py_files = list(find_python_files(include_tests=args.include_tests))
    java_root = REPO_ROOT / "plugins" / "ghidra"
    java_files: list[Path] = []
    if java_root.exists():
        for root, dirs, files in os.walk(java_root):
            dirs[:] = [
                d for d in dirs if d not in {".gradle", ".git", "bin", "build", "out"}
            ]
            for fname in files:
                if fname.endswith(".java"):
                    java_files.append(Path(root) / fname)

    modified = 0
    touched = 0
    for f in py_files:
        changed = process_file(f, header_lines, apply=args.apply)
        if changed:
            modified += 1
        touched += 1
    for jf in java_files:
        original = jf.read_text(encoding="utf-8")
        # quick skip if header already present
        if HEADER_MARKER in "\n".join(original.splitlines()[:80]):
            touched += 1
            continue
        changed = process_java_file(jf, header_java, apply=args.apply)
        if changed:
            modified += 1
        touched += 1

    action = "Modified" if args.apply else "Would modify"
    print(f"{action} {modified} of {touched} Python files.")
    if not args.apply and modified:
        print("Run with --apply to write changes.")
    if args.check and modified:
        # Non-zero exit to indicate failure in CI
        raise SystemExit(1)


if __name__ == "__main__":
    main()
