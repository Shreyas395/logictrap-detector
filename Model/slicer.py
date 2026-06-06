"""Backward slicer over the predicate of a candidate gate block.

Given a ``(gate_block_addr, sink_addr)`` pair from ``gate_locator``,
this module:

  1. Computes a backward slice of instructions reaching the predicate.
  2. Lifts to angr VEX IR.
  3. Pretty-prints to pseudo-C by shelling out to Ghidra headless
     (``analyzeHeadless`` + a small post-script).

Output is a ``GateSlice`` dataclass.
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
        raise NotImplementedError
