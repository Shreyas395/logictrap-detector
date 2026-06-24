"""Unit tests for the gate-characterization pipeline.

The pipeline glues four collaborators (slicer, scorer, characterizer,
plus an angr CFG). We supply small stand-ins for each so the loop's
control flow can be exercised in isolation.
"""
import pytest

from pipeline import characterize_gates
from scorer import GateScore


# --------------------------------------------------------------------- #
# stubs
# --------------------------------------------------------------------- #
class _StubExternalCall:
    def __init__(self, target_name):
        self.target_name = target_name


class _StubGateSlice:
    def __init__(self, gate_addr=0x401000, external_calls=None):
        self.gate_addr = gate_addr
        self.external_calls = external_calls or []


class _StubSlicer:
    """Records every slice request and returns a configurable slice."""

    def __init__(self, external_calls=None, raise_on_addrs=None):
        self.external_calls = external_calls or []
        self.raise_on_addrs = set(raise_on_addrs or [])
        self.calls = []

    def slice_gate(self, proj, gate_addr, sink_addr):
        self.calls.append((gate_addr, sink_addr))
        if gate_addr in self.raise_on_addrs:
            raise RuntimeError(f"simulated slice failure at {hex(gate_addr)}")
        return _StubGateSlice(gate_addr=gate_addr, external_calls=self.external_calls)


class _StubScorer:
    """Distance is dictated by a lookup table. Score is the
    SinkDistanceScorer formula so tests verify behavior end-to-end."""

    def __init__(self, distances):
        # distances: {(gate_addr, sink_addr): int}
        self.distances = distances

    def basic_blocks_between(self, cfg, src, dst):
        return self.distances.get((src, dst), 10)

    def score(self, gate_addr, sink_addr, gate_complexity, external_dep_count, basic_blocks_to_sink):
        bb = max(1, basic_blocks_to_sink)
        return GateScore(
            gate_addr=gate_addr,
            sink_addr=sink_addr,
            gate_complexity=gate_complexity,
            external_dep_count=external_dep_count,
            basic_blocks_to_sink=bb,
            score=(gate_complexity * external_dep_count) / bb,
        )


class _StubCharacterization:
    def __init__(self, gate_kind="env", bypass_difficulty="trivial", payload_class="shell-exec"):
        self.gate_kind = gate_kind
        self.external_deps = ["getenv"]
        self.bypass_difficulty = bypass_difficulty
        self.payload_class = payload_class
        self.why = "stub-explanation"
        self.model = "stub-model"


class _StubCharacterizer:
    def __init__(self, response=None, raise_on_addrs=None):
        self.response = response or _StubCharacterization()
        self.raise_on_addrs = set(raise_on_addrs or [])
        self.calls = 0

    def characterize(self, gate_slice):
        self.calls += 1
        if gate_slice.gate_addr in self.raise_on_addrs:
            raise RuntimeError(f"simulated char failure at {hex(gate_slice.gate_addr)}")
        return self.response


# --------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------- #
def _logic_traps(*specs):
    """Helper: build a logic_traps list from ``(addr, score)`` tuples."""
    return [(addr, {"score": score}) for addr, score in specs]


class TestCharacterizeGatesEmptyInputs:
    def test_no_traps_returns_empty(self):
        out = characterize_gates(
            proj=None, cfg=None,
            logic_traps=[], sink_addrs=[0x402000],
            slicer=_StubSlicer(), scorer=_StubScorer({}),
        )
        assert out == []

    def test_no_sinks_returns_empty(self):
        out = characterize_gates(
            proj=None, cfg=None,
            logic_traps=_logic_traps((0x401000, 5)),
            sink_addrs=[],
            slicer=_StubSlicer(), scorer=_StubScorer({}),
        )
        assert out == []


class TestNearestSinkSelection:
    def test_picks_closest_sink_for_each_trap(self):
        # Two sinks at addresses A and B; trap is 2 blocks from A, 8 from B.
        trap_addr = 0x401000
        sink_a = 0x402000
        sink_b = 0x403000
        scorer = _StubScorer({(trap_addr, sink_a): 2, (trap_addr, sink_b): 8})
        slicer = _StubSlicer(external_calls=[_StubExternalCall("getenv")])
        out = characterize_gates(
            proj=None, cfg=None,
            logic_traps=_logic_traps((trap_addr, 6)),
            sink_addrs=[sink_a, sink_b],
            slicer=slicer, scorer=scorer,
        )
        assert len(out) == 1
        assert out[0]["sink_addr"] == hex(sink_a)
        # slicer received the chosen pair
        assert slicer.calls == [(trap_addr, sink_a)]


class TestEntryShape:
    def test_keys_present_and_scores_computed(self):
        slicer = _StubSlicer(external_calls=[
            _StubExternalCall("getenv"),
            _StubExternalCall("strcmp"),
        ])
        scorer = _StubScorer({(0x401000, 0x402000): 4})
        out = characterize_gates(
            proj=None, cfg=None,
            logic_traps=_logic_traps((0x401000, 6)),
            sink_addrs=[0x402000],
            slicer=slicer, scorer=scorer,
        )
        assert len(out) == 1
        entry = out[0]
        assert entry["gate_addr"] == hex(0x401000)
        assert entry["sink_addr"] == hex(0x402000)
        assert entry["complexity"] == 6
        assert entry["external_deps"] == ["getenv", "strcmp"]
        assert entry["distance_to_sink"] == 4
        # (6 * 2) / 4 = 3.0
        assert entry["score"] == pytest.approx(3.0)
        assert "characterization" not in entry  # no characterizer passed


class TestCharacterizationOptional:
    def test_included_when_characterizer_returns(self):
        slicer = _StubSlicer(external_calls=[_StubExternalCall("getenv")])
        scorer = _StubScorer({(0x401000, 0x402000): 2})
        ch = _StubCharacterizer(_StubCharacterization(gate_kind="env", bypass_difficulty="env-controllable"))
        out = characterize_gates(
            proj=None, cfg=None,
            logic_traps=_logic_traps((0x401000, 4)),
            sink_addrs=[0x402000],
            slicer=slicer, scorer=scorer, characterizer=ch,
        )
        assert ch.calls == 1
        assert out[0]["characterization"]["gate_kind"] == "env"
        assert out[0]["characterization"]["bypass_difficulty"] == "env-controllable"

    def test_error_record_when_characterizer_raises(self):
        slicer = _StubSlicer()
        scorer = _StubScorer({(0x401000, 0x402000): 2})
        ch = _StubCharacterizer(raise_on_addrs=[0x401000])
        out = characterize_gates(
            proj=None, cfg=None,
            logic_traps=_logic_traps((0x401000, 4)),
            sink_addrs=[0x402000],
            slicer=slicer, scorer=scorer, characterizer=ch,
        )
        assert "error" in out[0]["characterization"]
        # entry still emitted; only the characterization is replaced with the error
        assert out[0]["gate_addr"] == hex(0x401000)


class TestSliceFailureSkipsGate:
    def test_failed_slice_drops_that_gate(self):
        slicer = _StubSlicer(raise_on_addrs=[0x401000])
        scorer = _StubScorer({(0x402000, 0x402100): 3})
        out = characterize_gates(
            proj=None, cfg=None,
            logic_traps=_logic_traps((0x401000, 6), (0x402000, 8)),
            sink_addrs=[0x402100],
            slicer=slicer, scorer=scorer,
        )
        # First trap fails -> only the second survives
        assert len(out) == 1
        assert out[0]["gate_addr"] == hex(0x402000)


class TestSortingByScore:
    def test_highest_score_first(self):
        # Two traps; second has higher external-dep count and is closer.
        slicer_a = _StubSlicer(external_calls=[_StubExternalCall("getenv")])
        # We can't easily pass two different slicers, so build a richer
        # stub that returns different external_calls per gate.
        class _MultiSlicer:
            def slice_gate(self, proj, gate_addr, sink_addr):
                if gate_addr == 0x401000:
                    return _StubGateSlice(gate_addr=gate_addr, external_calls=[_StubExternalCall("a")])
                return _StubGateSlice(
                    gate_addr=gate_addr,
                    external_calls=[_StubExternalCall("a"), _StubExternalCall("b"), _StubExternalCall("c")],
                )

        scorer = _StubScorer({
            (0x401000, 0x403000): 5,
            (0x402000, 0x403000): 2,
        })
        out = characterize_gates(
            proj=None, cfg=None,
            logic_traps=_logic_traps((0x401000, 4), (0x402000, 6)),
            sink_addrs=[0x403000],
            slicer=_MultiSlicer(), scorer=scorer,
        )
        assert len(out) == 2
        # Second gate: (6 * 3) / 2 = 9.0  > first: (4 * 1) / 5 = 0.8
        assert out[0]["gate_addr"] == hex(0x402000)
        assert out[1]["gate_addr"] == hex(0x401000)


class TestOnErrorCallback:
    def test_invoked_on_slice_failure(self):
        seen = []
        slicer = _StubSlicer(raise_on_addrs=[0x401000])
        scorer = _StubScorer({(0x401000, 0x402000): 3})
        characterize_gates(
            proj=None, cfg=None,
            logic_traps=_logic_traps((0x401000, 4)),
            sink_addrs=[0x402000],
            slicer=slicer, scorer=scorer,
            on_error=lambda addr, msg: seen.append((addr, msg)),
        )
        assert len(seen) == 1
        assert seen[0][0] == 0x401000
        assert "slice" in seen[0][1]

    def test_invoked_on_characterizer_failure(self):
        seen = []
        slicer = _StubSlicer()
        scorer = _StubScorer({(0x401000, 0x402000): 3})
        ch = _StubCharacterizer(raise_on_addrs=[0x401000])
        characterize_gates(
            proj=None, cfg=None,
            logic_traps=_logic_traps((0x401000, 4)),
            sink_addrs=[0x402000],
            slicer=slicer, scorer=scorer, characterizer=ch,
            on_error=lambda addr, msg: seen.append((addr, msg)),
        )
        assert len(seen) == 1
        assert "characterize" in seen[0][1]
