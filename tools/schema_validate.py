import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

try:
    from jsonschema import Draft7Validator
    from jsonschema.validators import validator_for
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False


def load_json(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def collect_files(patterns: List[str]) -> List[Path]:
    files: List[Path] = []
    for pat in patterns:
        files.extend(sorted(Path().glob(pat)))
    return [p for p in files if p.is_file() and p.suffix.lower() == ".json"]


def main(argv: List[str]) -> int:
    """
    Validate JSON artifacts against one or more JSON Schemas.

    Modes:
    - Flag-style: --targets <glob ...> --schemas <glob ...>
    - Positional: <artifacts_glob> <schemas_glob>

    Exit codes:
    - 0: all artifacts valid against at least one schema
    - 1: validation errors
    - 2: no schemas provided or matched
    """
    if not JSONSCHEMA_AVAILABLE:
        print("jsonschema library is not available", file=sys.stderr)
        return 2
    ap = argparse.ArgumentParser(description="Validate JSON artifacts against schemas")
    ap.add_argument("positional", nargs="*", help="[artifacts_glob] [schemas_glob]")
    ap.add_argument("--targets", nargs="+", help="Glob(s) for JSON files to validate")
    ap.add_argument("--schemas", nargs="+", help="Schema file(s) to use")
    ap.add_argument("--out", default="evidence/schema_validation.json", help="Output report path")
    args = ap.parse_args(argv)

    target_globs: List[str] = []
    schema_globs: List[str] = []
    if args.targets:
        target_globs.extend(args.targets)
    if args.schemas:
        schema_globs.extend(args.schemas)
    if args.positional:
        if len(args.positional) >= 2:
            target_globs.append(args.positional[0])
            schema_globs.append(args.positional[1])
        elif len(args.positional) == 1:
            target_globs.append(args.positional[0])

    artifact_paths = collect_files(target_globs)
    schema_paths = collect_files(schema_globs)

    if not schema_paths:
        print("No schema JSON files matched", file=sys.stderr)
        return 2
    if not artifact_paths:
        print("No artifact JSON files matched", file=sys.stderr)

    # Prepare validators by $id
    validators: Dict[str, Draft7Validator] = {}
    for sp in schema_paths:
        schema = load_json(sp)
        schema_id = schema.get("$id", str(sp.resolve()))
        # Use modern jsonschema API - no RefResolver needed for basic validation
        validator_cls = validator_for(schema)
        validators[schema_id] = validator_cls(schema)

    results: Dict[str, List[Dict]] = {"validated": [], "errors": []}
    for apath in artifact_paths:
        try:
            data = load_json(apath)
        except Exception as e:
            results["errors"].append({"file": str(apath), "error": f"load_error: {e}"})
            continue

        matched = False
        for schema_id, validator in validators.items():
            errs = sorted(validator.iter_errors(data), key=lambda e: e.path)
            if not errs:
                results["validated"].append({"file": str(apath), "schema": schema_id})
                matched = True
                break
        if not matched:
            # Collect errors from the first schema for debugging context
            schema_id, validator = next(iter(validators.items()))
            errs = [
                {"message": e.message, "path": list(e.path), "schema_path": list(e.schema_path)}
                for e in validator.iter_errors(load_json(apath))
            ]
            results["errors"].append({"file": str(apath), "schema": schema_id, "errors": errs})

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps({
        "summary": {
            "total": len(results.get("validated", [])) + len(results.get("errors", [])),
            "valid": len(results.get("validated", [])),
            "invalid": len(results.get("errors", []))
        },
        "output": str(out_path)
    }, indent=2))

    return 0 if not results["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
