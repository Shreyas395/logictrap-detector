"""Smoke tests for the bench harness.

Verifies that bench/run.py can locate and parse corpus manifests, and
that its JSON-coercion helper handles common edge cases. We deliberately
avoid running the full analyzer here — that requires angr and is the
heavy integration path.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_RUN = REPO_ROOT / "bench" / "run.py"
CORPUS_ROOT = REPO_ROOT / "corpus"


@pytest.fixture(scope="module")
def bench_run():
    """Import ``bench/run.py`` as a module without running ``main()``."""
    spec = importlib.util.spec_from_file_location("bench_run", BENCH_RUN)
    module = importlib.util.module_from_spec(spec)
    sys.modules["bench_run"] = module
    spec.loader.exec_module(module)
    return module


class TestLoadCategoryManifests:
    def test_yields_synthetic(self, bench_run):
        results = dict(bench_run.load_category_manifests(CORPUS_ROOT))
        assert "synthetic" in results
        assert isinstance(results["synthetic"], dict)

    def test_synthetic_manifest_has_samples_key(self, bench_run):
        results = dict(bench_run.load_category_manifests(CORPUS_ROOT))
        assert "samples" in results["synthetic"]
        assert isinstance(results["synthetic"]["samples"], list)

    def test_categories_without_manifest_are_skipped(self, bench_run, capsys):
        # corpus/xz/ and corpus/gadget-chains/ have READMEs but no
        # manifest.json yet — they should be skipped, not raise.
        results = dict(bench_run.load_category_manifests(CORPUS_ROOT))
        out = capsys.readouterr().out
        # Either skipped (and absent from results) or present — either is
        # fine if a manifest gets added later, but they must not crash.
        for category in ("xz", "gadget-chains", "negatives"):
            if category not in results:
                assert "skip" in out.lower() or category in out


class TestJsonable:
    def test_passes_primitives_through(self, bench_run):
        for v in (1, 1.5, "s", True, False, None):
            assert bench_run.jsonable(v) == v

    def test_nested_dict_is_serializable(self, bench_run):
        nested = {"a": [1, 2, {"b": ("x", "y")}], "c": None}
        result = bench_run.jsonable(nested)
        # Round-trip through json.dumps to verify serializability.
        json.dumps(result)
        assert result["c"] is None
        assert result["a"][2]["b"] == ["x", "y"]

    def test_non_serializable_objects_become_strings(self, bench_run):
        class Custom:
            def __repr__(self):
                return "<custom>"

        result = bench_run.jsonable(Custom())
        assert result == "<custom>"
        json.dumps(result)  # must be serializable now

    def test_dict_keys_coerced_to_str(self, bench_run):
        result = bench_run.jsonable({1: "a", 2: "b"})
        assert result == {"1": "a", "2": "b"}
        json.dumps(result)
