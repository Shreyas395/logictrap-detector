"""Unit tests for the sink-distance scorer."""
import pytest

from scorer import GateScore, SinkDistanceScorer


@pytest.fixture
def scorer():
    return SinkDistanceScorer()


class TestScoreFormula:
    def test_typical_case(self, scorer):
        s = scorer.score(
            gate_addr=0x401000,
            sink_addr=0x401200,
            gate_complexity=4,
            external_dep_count=3,
            basic_blocks_to_sink=2,
        )
        assert isinstance(s, GateScore)
        assert s.score == pytest.approx(6.0)
        assert s.gate_addr == 0x401000
        assert s.sink_addr == 0x401200
        assert s.basic_blocks_to_sink == 2

    def test_zero_external_deps_collapses_score(self, scorer):
        s = scorer.score(0, 0, gate_complexity=10, external_dep_count=0, basic_blocks_to_sink=2)
        assert s.score == 0.0

    def test_far_from_sink_pulls_score_down(self, scorer):
        near = scorer.score(0, 0, gate_complexity=4, external_dep_count=3, basic_blocks_to_sink=1).score
        far = scorer.score(0, 0, gate_complexity=4, external_dep_count=3, basic_blocks_to_sink=100).score
        assert near > far
        assert far == pytest.approx(0.12)

    def test_zero_bb_treated_as_one(self, scorer):
        """basic_blocks_to_sink == 0 must not divide-by-zero; it floors at 1."""
        s = scorer.score(0, 0, gate_complexity=4, external_dep_count=3, basic_blocks_to_sink=0)
        assert s.score == pytest.approx(12.0)
        assert s.basic_blocks_to_sink == 1

    def test_negative_bb_treated_as_one(self, scorer):
        s = scorer.score(0, 0, gate_complexity=4, external_dep_count=3, basic_blocks_to_sink=-5)
        assert s.score == pytest.approx(12.0)
        assert s.basic_blocks_to_sink == 1


class _StubNode:
    """Minimal CFG node fake — just has an ``addr`` attribute."""

    def __init__(self, addr: int):
        self.addr = addr


class _StubGraph:
    """Minimal networkx-like graph fake."""

    def __init__(self, nodes):
        self._nodes = list(nodes)

    def nodes(self):
        return list(self._nodes)


class _StubCFG:
    def __init__(self, nodes):
        self.graph = _StubGraph(nodes)


class TestBasicBlocksBetween:
    def test_missing_src_returns_sentinel(self):
        cfg = _StubCFG([_StubNode(0x1000), _StubNode(0x2000)])
        # 0xDEAD is not in the graph
        assert SinkDistanceScorer.basic_blocks_between(cfg, 0xDEAD, 0x2000) == 999

    def test_missing_dst_returns_sentinel(self):
        cfg = _StubCFG([_StubNode(0x1000), _StubNode(0x2000)])
        assert SinkDistanceScorer.basic_blocks_between(cfg, 0x1000, 0xBEEF) == 999

    def test_no_networkx_path_returns_sentinel(self):
        """Two unrelated nodes — no edges added — must surface 999 not crash."""
        cfg = _StubCFG([_StubNode(0x1000), _StubNode(0x2000)])
        # Both addrs exist; no edges means networkx raises NetworkXNoPath.
        # The helper should catch and return 999.
        assert SinkDistanceScorer.basic_blocks_between(cfg, 0x1000, 0x2000) == 999
