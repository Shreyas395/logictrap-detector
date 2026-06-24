"""End-to-end gate characterization pipeline.

Stitches together the four detector components into the canonical
JSON-shaped output documented in the project README:

    locate (gate_locator) ->
        slice (slicer) ->
            characterize (characterizer, optional) ->
                score (scorer)

Pulled out of the orchestrator so tests can exercise the loop with
plain stubs instead of spinning up a real angr ``Project``.
"""
import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

log = logging.getLogger(__name__)


def _nearest_sink(scorer, cfg, gate_addr: int, sink_addrs: Iterable[int]) -> Optional[int]:
    """Return the sink address with the smallest basic-block distance,
    or None if no sinks are provided."""
    best: Optional[int] = None
    best_dist = float("inf")
    for sink in sink_addrs:
        try:
            d = scorer.basic_blocks_between(cfg, gate_addr, sink)
        except Exception as e:
            log.debug(f"distance lookup failed for {hex(gate_addr)} -> {hex(sink)}: {e}")
            continue
        if d < best_dist:
            best = sink
            best_dist = d
    return best


def characterize_gates(
    proj,
    cfg,
    logic_traps: List[Tuple[int, Dict[str, Any]]],
    sink_addrs: Iterable[int],
    slicer,
    scorer,
    characterizer=None,
    on_error: Optional[Callable[[int, str], None]] = None,
) -> List[Dict[str, Any]]:
    """Run the slice -> score -> characterize loop for every trap.

    ``logic_traps``: ``[(gate_addr, info_dict), ...]`` from
    ``LogicTrapAnalyzer.find_logic_traps``. ``info_dict`` is expected to
    have at minimum a ``score`` integer (the gate's instruction-density
    score from the locator).

    ``sink_addrs``: an iterable of dangerous-function addresses from
    ``SinkFinder``. For each trap, the nearest sink in basic blocks is
    paired with it.

    ``characterizer`` is optional. If ``None`` or it raises during
    ``characterize``, the gate entry is emitted without a
    ``characterization`` field. ``on_error`` (optional) is invoked with
    ``(gate_addr, message)`` whenever any pipeline stage fails for a
    given gate so the caller can log it.
    """
    sink_addrs = list(sink_addrs)
    if not logic_traps or not sink_addrs:
        return []

    out: List[Dict[str, Any]] = []
    for trap_addr, trap_info in logic_traps:
        sink_addr = _nearest_sink(scorer, cfg, trap_addr, sink_addrs)
        if sink_addr is None:
            continue

        # --- slice ----------------------------------------------------
        try:
            gate_slice = slicer.slice_gate(proj, trap_addr, sink_addr)
        except Exception as e:
            log.debug(f"slice failed at {hex(trap_addr)}: {e}")
            if on_error:
                on_error(trap_addr, f"slice: {e}")
            continue

        external_deps = [
            getattr(ec, "target_name", "?")
            for ec in (gate_slice.external_calls or [])
        ]

        # --- score ----------------------------------------------------
        try:
            bb_dist = scorer.basic_blocks_between(cfg, trap_addr, sink_addr)
        except Exception as e:
            log.debug(f"distance lookup failed at {hex(trap_addr)}: {e}")
            bb_dist = 999
        gate_score = scorer.score(
            gate_addr=trap_addr,
            sink_addr=sink_addr,
            gate_complexity=int(trap_info.get("score", 0)),
            external_dep_count=len(external_deps),
            basic_blocks_to_sink=bb_dist,
        )

        entry: Dict[str, Any] = {
            "gate_addr": hex(trap_addr),
            "sink_addr": hex(sink_addr),
            "complexity": int(trap_info.get("score", 0)),
            "external_deps": external_deps,
            "distance_to_sink": gate_score.basic_blocks_to_sink,
            "score": gate_score.score,
        }

        # --- characterize (optional) ----------------------------------
        if characterizer is not None:
            try:
                char = characterizer.characterize(gate_slice)
                entry["characterization"] = {
                    "gate_kind": char.gate_kind,
                    "bypass_difficulty": char.bypass_difficulty,
                    "payload_class": char.payload_class,
                    "external_deps": char.external_deps,
                    "why": char.why,
                    "model": char.model,
                }
            except Exception as e:
                log.debug(f"characterize failed at {hex(trap_addr)}: {e}")
                if on_error:
                    on_error(trap_addr, f"characterize: {e}")
                entry["characterization"] = {"error": str(e)}

        out.append(entry)

    # Highest-score gate first — handy for both human review and any
    # caller that just wants the top-N.
    out.sort(key=lambda g: g.get("score", 0.0), reverse=True)
    return out
