"""Benchmark harness for logictrap-detector.

Iterates the corpus, runs the analyzer per sample, and emits per-sample
plus aggregate JSON. Currently dumps raw analyzer results; future
extension can compute recall, characterization F1, and false-positive
rate against the manifest ground-truth fields.

Usage:
    python bench/run.py                          # run everything
    python bench/run.py --filter synthetic       # one category
    python bench/run.py --filter pin_check_l4    # one sample
    python bench/run.py --out output/bench.json
"""
import argparse
import json
import sys
import time
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "Model"))


def load_category_manifests(corpus_root: Path):
    for category_dir in sorted(corpus_root.iterdir()):
        if not category_dir.is_dir():
            continue
        manifest_path = category_dir / "manifest.json"
        if not manifest_path.exists():
            print(f"[skip] {category_dir.name}/ has no manifest.json yet")
            continue
        with open(manifest_path, encoding="utf-8") as f:
            data = json.load(f)
        yield category_dir.name, data


def jsonable(value):
    """Best-effort: make a result tree JSON-serializable."""
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def run_sample(binary_path: Path, max_input_size: int) -> dict:
    if not binary_path.exists():
        return {"error": f"binary not found at {binary_path}"}
    # Lazy import: keeps angr off the module-load path so test runners
    # and ``--help`` don't pay the analyzer-import cost up front.
    from logictrapdetector import EnhancedShellPayloadAnalyzer

    analyzer = EnhancedShellPayloadAnalyzer(str(binary_path), max_input_size=max_input_size)
    t0 = time.monotonic()
    try:
        results = analyzer.analyze_enhanced()
    except Exception as exc:
        return {
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "elapsed_sec": time.monotonic() - t0,
        }
    results = jsonable(results)
    results["elapsed_sec"] = round(time.monotonic() - t0, 2)
    return results


def main():
    parser = argparse.ArgumentParser(description="Run logictrap-detector across the corpus.")
    parser.add_argument("--corpus", default=str(REPO_ROOT / "corpus"), help="Corpus root directory.")
    parser.add_argument("--out", default=str(REPO_ROOT / "output" / "bench_results.json"), help="Aggregate output JSON path.")
    parser.add_argument("--filter", default=None, help="Only run samples whose category or id contains this substring.")
    parser.add_argument("--max-input-size", type=int, default=256, help="Max symbolic input size passed to the analyzer.")
    args = parser.parse_args()

    corpus_root = Path(args.corpus)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    aggregate = {
        "started_at": time.time(),
        "corpus_root": str(corpus_root),
        "filter": args.filter,
        "runs": [],
    }

    for category, manifest in load_category_manifests(corpus_root):
        for sample in manifest.get("samples", []):
            sample_id = sample.get("id", "?")
            if args.filter and args.filter not in sample_id and args.filter not in category:
                continue

            binary_path = REPO_ROOT / sample["path"]
            print(f"\n{'=' * 60}\n[bench] {category}/{sample_id}  →  {binary_path}\n{'=' * 60}")

            result = run_sample(binary_path, args.max_input_size)
            aggregate["runs"].append({
                "id": sample_id,
                "category": category,
                "ground_truth": sample.get("ground_truth"),
                "result": result,
            })

            # Also drop a per-sample file so a long run isn't all-or-nothing.
            per_sample_path = out_path.parent / f"{sample_id}.json"
            with open(per_sample_path, "w", encoding="utf-8") as f:
                json.dump({"sample": sample, "result": result}, f, indent=2, default=str)

    aggregate["finished_at"] = time.time()
    aggregate["duration_sec"] = round(aggregate["finished_at"] - aggregate["started_at"], 2)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(aggregate, f, indent=2, default=str)

    print(f"\n[+] {len(aggregate['runs'])} samples completed in {aggregate['duration_sec']}s")
    print(f"[+] Aggregate written to {out_path}")


if __name__ == "__main__":
    main()
