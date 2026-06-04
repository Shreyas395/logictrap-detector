"""Backward slicer over the predicate of a candidate gate block.

Stub for week 4. Given a (gate_block_addr, sink_addr) pair from
gate_locator.LogicTrapAnalyzer, this module will:

  1. Compute a backward slice of instructions reaching the predicate.
  2. Lift to angr VEX IR.
  3. Pretty-print as pseudo-C by shelling out to Ghidra headless
     (`analyzeHeadless` + a small post-script). Ghidra is the right
     free dependency here — no API keys, runs locally, scriptable.

Output is a `GateSlice` dataclass consumed by characterizer.py.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class GateSlice:
    gate_addr: int
    sink_addr: int
    slice_blocks: List[int] = field(default_factory=list)
    vex_ir: str = ""
    pseudo_c: str = ""
    external_calls: List[Dict[str, Any]] = field(default_factory=list)


class GateSlicer:
    def __init__(self, ghidra_headless_path: str = "", project_dir: str = ""):
        self.ghidra_headless_path = ghidra_headless_path
        self.project_dir = project_dir

    def slice_gate(self, proj, gate_addr: int, sink_addr: int) -> GateSlice:
        raise NotImplementedError("week 4 deliverable")
