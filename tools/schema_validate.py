import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

from jsonschema import Draft7Validator


def load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("positional", nargs="*", help="[targets_glob ...] [schemas_glob ...]")
    ap.add_argument("--targets", nargs="+", help="Glob(s) for JSON files to validate")
    ap.add_argument("--schemas", nargs="+", help="Schema file(s) to use")
    ap.add_argument("--out", default="evidence/schema_validation.json")
    args = ap.parse_args(argv)

    # Support both flag-style and positional args for compatibility with `python -m tools.schema_validate <targets> <schemas>`
    targets_globs: List[str] = []
    schemas_globs: List[str] = []
    if args.targets:
        targets_globs = args.targets
    if args.schemas:
        schemas_globs = args.schemas
    if args.positional:
        # split half-half if two groups given, else treat first as targets and second as schemas
        if len(args.positional) >= 2:
            targets_globs.append(args.positional[0])
            schemas_globs.append(args.positional[1])
        else:
            targets_globs.extend(args.positional)

    target_files: List[Path] = []
    for g in targets_globs:
        target_files.extend(Path().glob(g))

    schema_files: List[Path] = []
    for g in schemas_globs:
        schema_files.extend(Path().glob(g))

    validators = [Draft7Validator(load_json(p)) for p in schema_files]

    results = []
    all_ok = True
    for tf in target_files:
        try:
            data = load_json(tf)
        except Exception as e:
            results.append({"file": str(tf), "valid": False, "error": f"load_error: {e}"})
            all_ok = False
            continue
        file_ok = True
        errors: List[str] = []
        for v in validators:
            errs = sorted(v.iter_errors(data), key=lambda e: e.path)
            if errs:
                file_ok = False
                errors.extend([f"{e.message} at {'/'.join(map(str, e.path))}" for e in errs])
        results.append({"file": str(tf), "valid": file_ok, "errors": errors})
        all_ok = all_ok and file_ok

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"results": results}, indent=2), encoding="utf-8")
    print(json.dumps({"summary": {"total": len(results), "valid": sum(1 for r in results if r['valid'])}}, indent=2))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
import argparse
import json
import sys
from pathlib import Path
from typing import List

from jsonschema import Draft7Validator, RefResolver


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def collect_files(patterns: List[str]) -> List[Path]:
    files: List[Path] = []
    for pat in patterns:
        # Support Windows-style globs from pwsh by expanding here
        p = Path().glob(pat)
        files.extend(sorted(p))
    return [p for p in files if p.is_file() and p.suffix.lower() == ".json"]


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate JSON artifacts against schemas")
    parser.add_argument("artifacts", nargs="+", help="Glob(s) of JSON files to validate (artifacts)")
    parser.add_argument("schemas", nargs="+", help="Glob(s) of JSON Schema files")
    parser.add_argument("--out", default="evidence/schema_validation.json", help="Output report path")
    args = parser.parse_args(argv)

    artifact_paths = collect_files(args.artifacts)
    schema_paths = collect_files(args.schemas)

    if not artifact_paths:
        print("No artifact JSON files matched", file=sys.stderr)
    if not schema_paths:
        print("No schema JSON files matched", file=sys.stderr)
        return 2

    # Build validators by $id
    validators = {}
    for sp in schema_paths:
        schema = load_json(sp)
        schema_id = schema.get("$id", str(sp.resolve()))
        resolver = RefResolver.from_schema(schema)
        validators[schema_id] = Draft7Validator(schema, resolver=resolver)

    results = {"validated": [], "errors": []}
    for ap in artifact_paths:
        try:
            data = load_json(ap)
        except Exception as e:
            results["errors"].append({"file": str(ap), "error": f"load_error: {e}"})
            continue
        matched = False
        for schema_id, validator in validators.items():
            errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
            if not errors:
                results["validated"].append({"file": str(ap), "schema": schema_id})
                matched = True
                break
        if not matched:
            # Collect first schema's errors for debugging
            schema_id, validator = next(iter(validators.items()))
            errors = [
                {
                    "message": e.message,
                    "path": list(e.path),
                    "schema_path": list(e.schema_path),
                }
                for e in validator.iter_errors(data)
            ]
            results["errors"].append({"file": str(ap), "schema": schema_id, "errors": errors})

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Wrote schema validation report to {out_path}")
    return 0 if not results["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
