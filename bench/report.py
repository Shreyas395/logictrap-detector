"""Aggregate reporter for ``bench/run.py`` output.

Reads ``output/bench_results.json`` and prints per-category and overall
metrics:

  - number of samples processed, skipped, errored
  - total gates flagged
  - **recall** on payload-bearing samples (did at least one gate get
    flagged for each labelled sample?)
  - **false-positive rate** on ``has_payload: false`` samples
    (gates flagged above the per-sample expected upper bound)
  - **characterization match** counts where a sample's ground truth
    sets ``gate_kinds`` / ``bypass_difficulty`` / ``sink_class`` and
    the characterizer produced a matching value

Usage::

    python bench/report.py
    python bench/report.py --results output/bench_results.json
    python bench/report.py --json output/bench_summary.json
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS = REPO_ROOT / "output" / "bench_results.json"


def _result_gates(run: Dict[str, Any]) -> List[Dict[str, Any]]:
    return run.get("result", {}).get("gates", []) or []


def _ground_truth(run: Dict[str, Any]) -> Dict[str, Any]:
    return run.get("ground_truth") or {}


def _sample_errored(run: Dict[str, Any]) -> bool:
    err = run.get("result", {}).get("error")
    return bool(err)


def summarize(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute the aggregate metrics dictionary."""
    by_cat: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "samples_total": 0,
        "samples_errored": 0,
        "gates_flagged": 0,
        "positive_samples": 0,
        "positive_samples_recalled": 0,
        "negative_samples": 0,
        "false_positive_samples": 0,
        "false_positives": 0,
        "characterization_matches": {
            "gate_kind": 0,
            "bypass_difficulty": 0,
            "sink_class": 0,
        },
        "characterization_attempts": {
            "gate_kind": 0,
            "bypass_difficulty": 0,
            "sink_class": 0,
        },
    })

    for run in runs:
        category = run.get("category", "uncategorized")
        bucket = by_cat[category]
        bucket["samples_total"] += 1

        if _sample_errored(run):
            bucket["samples_errored"] += 1
            continue

        gates = _result_gates(run)
        bucket["gates_flagged"] += len(gates)
        gt = _ground_truth(run)
        has_payload = gt.get("has_payload")

        if has_payload is True:
            bucket["positive_samples"] += 1
            if len(gates) > 0:
                bucket["positive_samples_recalled"] += 1
            _tally_characterization(bucket, gates, gt)
        elif has_payload is False:
            bucket["negative_samples"] += 1
            upper = int(gt.get("expected_gates_flagged_upper_bound", 0))
            extra = max(0, len(gates) - upper)
            if extra > 0:
                bucket["false_positive_samples"] += 1
                bucket["false_positives"] += extra

    overall = _aggregate_overall(by_cat)
    return {
        "by_category": dict(by_cat),
        "overall": overall,
    }


def _tally_characterization(
    bucket: Dict[str, Any],
    gates: List[Dict[str, Any]],
    gt: Dict[str, Any],
) -> None:
    if not gates:
        return
    # We compare against the *top-ranked* gate (highest score). The
    # pipeline already sorts gates descending by score before returning.
    top = gates[0]
    char = top.get("characterization") or {}
    if not isinstance(char, dict):
        return

    if "gate_kinds" in gt and isinstance(gt["gate_kinds"], list):
        bucket["characterization_attempts"]["gate_kind"] += 1
        if char.get("gate_kind") in gt["gate_kinds"]:
            bucket["characterization_matches"]["gate_kind"] += 1

    if "bypass_difficulty" in gt:
        bucket["characterization_attempts"]["bypass_difficulty"] += 1
        if char.get("bypass_difficulty") == gt["bypass_difficulty"]:
            bucket["characterization_matches"]["bypass_difficulty"] += 1

    if "sink_class" in gt:
        bucket["characterization_attempts"]["sink_class"] += 1
        if char.get("payload_class") == gt["sink_class"]:
            bucket["characterization_matches"]["sink_class"] += 1


def _aggregate_overall(by_cat: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    total = {
        "samples_total": 0,
        "samples_errored": 0,
        "gates_flagged": 0,
        "positive_samples": 0,
        "positive_samples_recalled": 0,
        "negative_samples": 0,
        "false_positive_samples": 0,
        "false_positives": 0,
        "characterization_matches": {"gate_kind": 0, "bypass_difficulty": 0, "sink_class": 0},
        "characterization_attempts": {"gate_kind": 0, "bypass_difficulty": 0, "sink_class": 0},
    }
    for cat in by_cat.values():
        for key in ("samples_total", "samples_errored", "gates_flagged",
                    "positive_samples", "positive_samples_recalled",
                    "negative_samples", "false_positive_samples", "false_positives"):
            total[key] += cat[key]
        for field in ("gate_kind", "bypass_difficulty", "sink_class"):
            total["characterization_matches"][field] += cat["characterization_matches"][field]
            total["characterization_attempts"][field] += cat["characterization_attempts"][field]
    return total


def _pct(num: int, denom: int) -> str:
    if denom == 0:
        return "n/a"
    return f"{(num / denom) * 100:.1f}%"


def render_text(summary: Dict[str, Any]) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append("logictrap-detector benchmark summary")
    lines.append("=" * 60)
    for category, c in sorted(summary["by_category"].items()):
        lines.append("")
        lines.append(f"[{category}]")
        lines.append(f"  samples processed:  {c['samples_total']} ({c['samples_errored']} errored)")
        lines.append(f"  gates flagged:      {c['gates_flagged']}")
        if c["positive_samples"]:
            recall = _pct(c["positive_samples_recalled"], c["positive_samples"])
            lines.append(f"  recall (payload):   {recall}  "
                         f"({c['positive_samples_recalled']}/{c['positive_samples']})")
        if c["negative_samples"]:
            fp_rate = _pct(c["false_positive_samples"], c["negative_samples"])
            lines.append(f"  FP rate (clean):    {fp_rate}  "
                         f"({c['false_positive_samples']}/{c['negative_samples']} samples, "
                         f"{c['false_positives']} excess flags)")
        if any(c["characterization_attempts"].values()):
            lines.append("  characterization match:")
            for field in ("gate_kind", "bypass_difficulty", "sink_class"):
                attempts = c["characterization_attempts"][field]
                matches = c["characterization_matches"][field]
                if attempts:
                    lines.append(f"    {field:18s} {_pct(matches, attempts)}  ({matches}/{attempts})")

    o = summary["overall"]
    lines.append("")
    lines.append("[overall]")
    lines.append(f"  samples processed:  {o['samples_total']} ({o['samples_errored']} errored)")
    lines.append(f"  gates flagged:      {o['gates_flagged']}")
    if o["positive_samples"]:
        lines.append(f"  recall (payload):   {_pct(o['positive_samples_recalled'], o['positive_samples'])}")
    if o["negative_samples"]:
        lines.append(f"  FP rate (clean):    {_pct(o['false_positive_samples'], o['negative_samples'])}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize a bench/run.py results JSON.")
    parser.add_argument("--results", default=str(DEFAULT_RESULTS),
                        help="Path to bench_results.json.")
    parser.add_argument("--json", default=None,
                        help="Optional path to also write a JSON summary.")
    args = parser.parse_args(argv)

    results_path = Path(args.results)
    if not results_path.exists():
        print(f"results file not found: {results_path}", file=sys.stderr)
        return 1
    with open(results_path, encoding="utf-8") as f:
        data = json.load(f)
    runs = data.get("runs", [])
    summary = summarize(runs)

    print(render_text(summary))

    if args.json:
        out_path = Path(args.json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"\n[+] wrote JSON summary to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
