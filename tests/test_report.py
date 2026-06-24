"""Unit tests for the bench reporter."""
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_REPORT = REPO_ROOT / "bench" / "report.py"


@pytest.fixture(scope="module")
def report_module():
    """Import ``bench/report.py`` without invoking main()."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("bench_report", BENCH_REPORT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bench_report"] = mod
    spec.loader.exec_module(mod)
    return mod


def _run(category, sample_id, ground_truth=None, gates=None, errored=False):
    """Build one entry in the ``runs`` list of bench_results.json."""
    result = {"binary_path": f"corpus/{category}/{sample_id}", "gates": gates or []}
    if errored:
        result = {"error": "boom"}
    return {
        "id": sample_id,
        "category": category,
        "ground_truth": ground_truth,
        "result": result,
    }


def _gate(score=1.0, characterization=None):
    g = {"gate_addr": "0x401000", "sink_addr": "0x402000", "score": score}
    if characterization is not None:
        g["characterization"] = characterization
    return g


class TestEmptyInput:
    def test_no_runs(self, report_module):
        summary = report_module.summarize([])
        assert summary["overall"]["samples_total"] == 0
        assert summary["by_category"] == {}


class TestSampleCounting:
    def test_counts_per_category(self, report_module):
        runs = [
            _run("synthetic", "a"),
            _run("synthetic", "b"),
            _run("xz", "c"),
        ]
        summary = report_module.summarize(runs)
        assert summary["by_category"]["synthetic"]["samples_total"] == 2
        assert summary["by_category"]["xz"]["samples_total"] == 1
        assert summary["overall"]["samples_total"] == 3

    def test_errored_samples_counted_separately(self, report_module):
        runs = [_run("synthetic", "a", errored=True), _run("synthetic", "b")]
        summary = report_module.summarize(runs)
        assert summary["by_category"]["synthetic"]["samples_errored"] == 1
        assert summary["by_category"]["synthetic"]["samples_total"] == 2


class TestRecall:
    def test_recall_payload_sample_with_gates(self, report_module):
        runs = [
            _run("synthetic", "good", ground_truth={"has_payload": True}, gates=[_gate(score=5.0)]),
        ]
        s = report_module.summarize(runs)
        cat = s["by_category"]["synthetic"]
        assert cat["positive_samples"] == 1
        assert cat["positive_samples_recalled"] == 1

    def test_recall_payload_sample_with_no_gates(self, report_module):
        runs = [
            _run("synthetic", "missed", ground_truth={"has_payload": True}, gates=[]),
        ]
        s = report_module.summarize(runs)
        cat = s["by_category"]["synthetic"]
        assert cat["positive_samples"] == 1
        assert cat["positive_samples_recalled"] == 0


class TestFalsePositives:
    def test_fp_above_upper_bound(self, report_module):
        # Upper bound is 1; we flagged 3 -> 2 excess flags.
        runs = [_run("negatives", "ls",
                     ground_truth={"has_payload": False, "expected_gates_flagged_upper_bound": 1},
                     gates=[_gate(), _gate(), _gate()])]
        s = report_module.summarize(runs)
        cat = s["by_category"]["negatives"]
        assert cat["negative_samples"] == 1
        assert cat["false_positive_samples"] == 1
        assert cat["false_positives"] == 2

    def test_no_fp_when_under_bound(self, report_module):
        runs = [_run("negatives", "ls",
                     ground_truth={"has_payload": False, "expected_gates_flagged_upper_bound": 3},
                     gates=[_gate(), _gate()])]
        s = report_module.summarize(runs)
        cat = s["by_category"]["negatives"]
        assert cat["false_positive_samples"] == 0
        assert cat["false_positives"] == 0

    def test_no_fp_when_under_default_bound_zero(self, report_module):
        # No upper_bound supplied; default is 0. Zero gates -> no FP.
        runs = [_run("negatives", "ls",
                     ground_truth={"has_payload": False},
                     gates=[])]
        s = report_module.summarize(runs)
        cat = s["by_category"]["negatives"]
        assert cat["false_positives"] == 0


class TestCharacterizationMatching:
    def test_matches_when_gate_kind_in_list(self, report_module):
        runs = [_run(
            "synthetic", "ok",
            ground_truth={
                "has_payload": True,
                "gate_kinds": ["env", "mixed"],
                "bypass_difficulty": "env-controllable",
                "sink_class": "shell-exec",
            },
            gates=[_gate(score=5.0, characterization={
                "gate_kind": "env",
                "bypass_difficulty": "env-controllable",
                "payload_class": "shell-exec",
            })],
        )]
        s = report_module.summarize(runs)
        cat = s["by_category"]["synthetic"]
        assert cat["characterization_matches"]["gate_kind"] == 1
        assert cat["characterization_matches"]["bypass_difficulty"] == 1
        assert cat["characterization_matches"]["sink_class"] == 1
        # attempts increment in lockstep with the gt fields being present
        assert cat["characterization_attempts"]["gate_kind"] == 1
        assert cat["characterization_attempts"]["bypass_difficulty"] == 1
        assert cat["characterization_attempts"]["sink_class"] == 1

    def test_no_match_when_value_diverges(self, report_module):
        runs = [_run(
            "synthetic", "off",
            ground_truth={
                "has_payload": True,
                "gate_kinds": ["env"],
                "bypass_difficulty": "trivial",
            },
            gates=[_gate(score=5.0, characterization={
                "gate_kind": "crypto",
                "bypass_difficulty": "crypto-hard",
                "payload_class": "shell-exec",
            })],
        )]
        s = report_module.summarize(runs)
        cat = s["by_category"]["synthetic"]
        assert cat["characterization_matches"]["gate_kind"] == 0
        assert cat["characterization_matches"]["bypass_difficulty"] == 0

    def test_compares_top_ranked_gate_only(self, report_module):
        # Only the highest-scored gate's characterization is checked
        # (the pipeline already sorts so gates[0] is the top).
        runs = [_run(
            "synthetic", "mixed",
            ground_truth={"has_payload": True, "gate_kinds": ["env"]},
            gates=[
                _gate(score=9.0, characterization={"gate_kind": "env"}),
                _gate(score=0.5, characterization={"gate_kind": "crypto"}),
            ],
        )]
        s = report_module.summarize(runs)
        cat = s["by_category"]["synthetic"]
        assert cat["characterization_matches"]["gate_kind"] == 1


class TestOverallAggregation:
    def test_overall_sums_categories(self, report_module):
        runs = [
            _run("synthetic", "a", ground_truth={"has_payload": True}, gates=[_gate()]),
            _run("xz", "b", ground_truth={"has_payload": True}, gates=[_gate(), _gate()]),
            _run("negatives", "c", ground_truth={"has_payload": False}, gates=[_gate()]),
        ]
        s = report_module.summarize(runs)
        assert s["overall"]["samples_total"] == 3
        assert s["overall"]["gates_flagged"] == 4
        assert s["overall"]["positive_samples"] == 2
        assert s["overall"]["positive_samples_recalled"] == 2
        assert s["overall"]["negative_samples"] == 1


class TestRendering:
    def test_text_renders_summary(self, report_module):
        runs = [
            _run("synthetic", "a", ground_truth={"has_payload": True}, gates=[_gate(score=5.0)]),
        ]
        s = report_module.summarize(runs)
        text = report_module.render_text(s)
        assert "[synthetic]" in text
        assert "[overall]" in text
        assert "recall" in text


class TestEndToEndJson:
    def test_round_trip_via_main(self, report_module, tmp_path, capsys):
        results_path = tmp_path / "results.json"
        summary_path = tmp_path / "summary.json"
        data = {
            "runs": [
                _run("synthetic", "a", ground_truth={"has_payload": True}, gates=[_gate()]),
            ],
        }
        results_path.write_text(json.dumps(data))
        rc = report_module.main(["--results", str(results_path), "--json", str(summary_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "samples processed" in out
        summary = json.loads(summary_path.read_text())
        assert summary["overall"]["samples_total"] == 1

    def test_missing_results_returns_nonzero(self, report_module, tmp_path, capsys):
        rc = report_module.main(["--results", str(tmp_path / "nope.json")])
        assert rc == 1
