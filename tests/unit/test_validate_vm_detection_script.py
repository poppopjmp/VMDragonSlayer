import json
from pathlib import Path

from tools.validate_vm_detection import main as validate_main


def test_vm_detection_validation_end_to_end(tmp_path: Path):
    registry = Path("data/samples/sample_registry.json")
    assert registry.exists(), "sample registry missing"

    # Load registry and synthesize predictions (predict positive for all entries)
    data = json.loads(registry.read_text(encoding="utf-8"))

    pred_dir = tmp_path / "preds"
    pred_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for key, items in data.items():
        if key == "metadata" or not isinstance(items, list):
            continue
        for it in items:
            h = str(it.get("hash", ""))
            if not h:
                continue
            obj = {"hash": h, "vm_detected": True, "confidence": 0.99}
            (pred_dir / f"{h}.json").write_text(json.dumps(obj), encoding="utf-8")
            count += 1

    assert count > 0, "no samples found in registry to validate"

    reports_dir = tmp_path / "reports"

    # Run validation script via its main() entrypoint
    args = [
        "--registry",
        str(registry),
        "--predictions-dir",
        str(pred_dir),
        "--reports-dir",
        str(reports_dir),
    ]

    # Patch argv for the script main
    import sys

    old_argv = sys.argv
    try:
        sys.argv = ["validate_vm_detection.py", *args]
        rc = validate_main()
        assert rc == 0
    finally:
        sys.argv = old_argv

    metrics_path = reports_dir / "vm_detect_metrics.json"
    assert metrics_path.exists(), "metrics json not generated"

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    assert "precision" in metrics and "recall" in metrics
    assert metrics.get("acceptance", {}).get("passed") in (True, False)
