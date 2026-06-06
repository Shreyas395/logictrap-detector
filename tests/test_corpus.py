"""Validate the corpus directory structure and manifest schema."""
import json
from pathlib import Path

import pytest

from characterizer import BYPASS_DIFFICULTIES, GATE_KINDS, PAYLOAD_CLASSES

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_ROOT = REPO_ROOT / "corpus"
SYNTHETIC_MANIFEST = CORPUS_ROOT / "synthetic" / "manifest.json"


def _load_synthetic_samples():
    with open(SYNTHETIC_MANIFEST, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("samples", [])


def test_synthetic_manifest_exists():
    assert SYNTHETIC_MANIFEST.exists(), f"missing manifest at {SYNTHETIC_MANIFEST}"


def test_synthetic_manifest_is_valid_json():
    with open(SYNTHETIC_MANIFEST, encoding="utf-8") as f:
        json.load(f)


def test_synthetic_manifest_has_samples():
    samples = _load_synthetic_samples()
    assert len(samples) >= 1, "synthetic manifest must list at least one sample"


@pytest.mark.parametrize("sample", _load_synthetic_samples(), ids=lambda s: s.get("id", "?"))
class TestSyntheticSampleSchema:
    REQUIRED_KEYS = {"id", "path", "source", "ground_truth"}
    REQUIRED_GT_KEYS = {"has_payload", "sink_class", "gate_kinds", "bypass_difficulty"}

    def test_required_keys_present(self, sample):
        missing = self.REQUIRED_KEYS - set(sample)
        assert not missing, f"sample {sample.get('id', '?')} missing keys: {missing}"

    def test_referenced_binary_exists(self, sample):
        binary = REPO_ROOT / sample["path"]
        assert binary.exists(), f"binary not found at {binary}"

    def test_referenced_source_exists(self, sample):
        source = REPO_ROOT / sample["source"]
        assert source.exists(), f"source not found at {source}"

    def test_ground_truth_keys_present(self, sample):
        gt = sample["ground_truth"]
        missing = self.REQUIRED_GT_KEYS - set(gt)
        assert not missing, f"ground_truth for {sample['id']} missing keys: {missing}"

    def test_gate_kinds_are_known_enum_values(self, sample):
        for kind in sample["ground_truth"]["gate_kinds"]:
            assert kind in GATE_KINDS, f"unknown gate_kind {kind!r}"

    def test_bypass_difficulty_is_known(self, sample):
        diff = sample["ground_truth"]["bypass_difficulty"]
        assert diff in BYPASS_DIFFICULTIES, f"unknown bypass_difficulty {diff!r}"

    def test_sink_class_is_known(self, sample):
        sink = sample["ground_truth"]["sink_class"]
        assert sink in PAYLOAD_CLASSES, f"unknown sink_class {sink!r}"
