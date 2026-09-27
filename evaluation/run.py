"""Reproduce development and holdout confusion matrices using the Python scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentshield.scanner import scan_text

HERE = Path(__file__).resolve().parent


def evaluate(name: str, file: str) -> dict:
    cases = json.loads((HERE / file).read_text(encoding="utf-8"))
    if not isinstance(cases, list) or any(not isinstance(c.get("text"), str) or not isinstance(c.get("attack"), bool) for c in cases):
        raise ValueError("Invalid labeled fixture corpus")
    outcomes = []
    for case in cases:
        report = scan_text(case["text"])
        outcomes.append({"id": case["id"], "channel": case["channel"], "expected_attack": case["attack"],
                         "flagged": report["score"] >= 20, "score": report["score"], "level": report["level"],
                         "signal_ids": [item["id"] for item in report["findings"]]})
    count = lambda attack, flagged: sum(c["expected_attack"] == attack and c["flagged"] == flagged for c in outcomes)
    tp, fp, tn, fn = count(True, True), count(False, True), count(False, False), count(True, False)
    ratio = lambda a, b: round(a / b, 3) if b else None
    return {"name": name, "sample_size": len(cases), "true_positive": tp, "false_positive": fp,
            "true_negative": tn, "false_negative": fn, "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn), "specificity": ratio(tn, tn + fp), "cases": outcomes}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Update evaluation/results.json")
    parser.add_argument("--check", action="store_true", help="Fail if checked-in results differ")
    args = parser.parse_args()
    report = {
        "method": "Hand-labeled synthetic examples; threshold score >= 20. Development cases informed the rules; holdout cases were run after the changes. Neither set measures real-world robustness.",
        "development": evaluate("development", "cases.json"),
        "holdout": evaluate("holdout", "holdout.json"),
    }
    serialized = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    path = HERE / "results.json"
    if args.write:
        path.write_text(serialized, encoding="utf-8")
    if args.check and path.read_text(encoding="utf-8") != serialized:
        raise SystemExit("Checked-in evaluation differs: rerun python -m evaluation.run --write")
    for name in ("development", "holdout"):
        print(json.dumps({key: value for key, value in report[name].items() if key != "cases"}))


if __name__ == "__main__":
    main()
