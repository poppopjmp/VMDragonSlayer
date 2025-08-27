import json
import sys
from pathlib import Path

import pytest

from tools import schema_validate


def write_json(tmp_path: Path, name: str, obj: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def run_validator(args):
    return schema_validate.main(args)


def test_schema_validate_flag_and_positional(tmp_path: Path, monkeypatch):
    # Build schema and artifacts
    schema = {"$id": "test://schema", "type": "object", "properties": {"a": {"type": "number"}}, "required": ["a"]}
    good = {"a": 1}
    bad = {"b": 2}

    s = write_json(tmp_path, "schema.json", schema)
    g = write_json(tmp_path, "good.json", good)
    b = write_json(tmp_path, "bad.json", bad)

    # Change cwd to tmp so globs resolve simply
    monkeypatch.chdir(tmp_path)

    # Flag style
    code1 = run_validator(["--targets", "*.json", "--schemas", "schema.json", "--out", "out1.json"])
    assert code1 == 1  # one invalid
    out1 = json.loads(Path("out1.json").read_text(encoding="utf-8"))
    assert any(v["file"].endswith("good.json") for v in out1["validated"]) 
    assert any(e["file"].endswith("bad.json") for e in out1["errors"]) 

    # Positional style
    code2 = run_validator(["*.json", "schema.json", "--out", "out2.json"])
    assert code2 == 1
    out2 = json.loads(Path("out2.json").read_text(encoding="utf-8"))
    assert "validated" in out2 and "errors" in out2
