"""Backward slicer over the predicate of a candidate gate block.

Given a ``(gate_block_addr, sink_addr)`` pair from ``gate_locator``,
this module:

  1. Computes a backward slice of basic blocks reaching the predicate
     by BFS through the CFG (bounded by ``max_slice_hops``).
  2. Lifts each slice block to angr VEX IR.
  3. Resolves external-call targets in the slice into structured
     ``ExternalCall`` records.
  4. Optionally pretty-prints to pseudo-C by shelling out to Ghidra
     headless (``analyzeHeadless`` + a small post-script). Requires
     ``GHIDRA_INSTALL_DIR`` to be set; falls back to a raw VEX dump
     when Ghidra is not available.

Output is a ``GateSlice`` dataclass.
"""
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger(__name__)


GHIDRA_TIMEOUT_DEFAULT = 180


@dataclass
class ExternalCall:
    """A call instruction in the slice that targets an external function."""

    addr: int
    target_name: str
    args: List[str] = field(default_factory=list)


@dataclass
class GateSlice:
    gate_addr: int
    sink_addr: int
    slice_blocks: List[int] = field(default_factory=list)
    vex_ir: str = ""
    pseudo_c: str = ""
    external_calls: List[ExternalCall] = field(default_factory=list)


class GateSlicer:
    def __init__(
        self,
        ghidra_install_dir: Optional[str] = None,
        max_slice_hops: int = 8,
        ghidra_timeout: int = GHIDRA_TIMEOUT_DEFAULT,
    ):
        self.ghidra_install_dir = (
            ghidra_install_dir
            if ghidra_install_dir is not None
            else os.environ.get("GHIDRA_INSTALL_DIR", "")
        )
        self.max_slice_hops = max(1, int(max_slice_hops))
        self.ghidra_timeout = int(ghidra_timeout)

    # ------------------------------------------------------------------ #
    # public entry point
    # ------------------------------------------------------------------ #
    def slice_gate(self, proj, gate_addr: int, sink_addr: int) -> GateSlice:
        cfg = self._get_cfg(proj)
        slice_blocks = self._walk_backward(cfg, gate_addr)
        vex_ir = self._lift_to_vex(proj, slice_blocks)
        external_calls = self._find_external_calls(proj, slice_blocks)
        pseudo_c = ""
        if self.ghidra_install_dir:
            pseudo_c = self._try_ghidra(proj, slice_blocks)
        if not pseudo_c:
            pseudo_c = vex_ir  # graceful fallback
        return GateSlice(
            gate_addr=gate_addr,
            sink_addr=sink_addr,
            slice_blocks=list(slice_blocks),
            vex_ir=vex_ir,
            pseudo_c=pseudo_c,
            external_calls=external_calls,
        )

    # ------------------------------------------------------------------ #
    # backward CFG walk
    # ------------------------------------------------------------------ #
    def _get_cfg(self, proj):
        try:
            cached = proj.kb.cfgs.get_most_accurate()
            if cached is not None:
                return cached
        except Exception as e:
            log.debug(f"no cached CFG: {e}")
        return proj.analyses.CFGFast(normalize=True)

    def _walk_backward(self, cfg, gate_addr: int) -> List[int]:
        target_node = self._find_node(cfg, gate_addr)
        if target_node is None:
            return [gate_addr]

        visited: Set[int] = {target_node.addr}
        order: List[int] = [target_node.addr]
        frontier = [target_node]
        for _ in range(self.max_slice_hops):
            next_frontier = []
            for node in frontier:
                preds = self._predecessors(cfg, node)
                for pred in preds:
                    pred_addr = getattr(pred, "addr", None)
                    if pred_addr is None or pred_addr in visited:
                        continue
                    visited.add(pred_addr)
                    order.append(pred_addr)
                    next_frontier.append(pred)
            if not next_frontier:
                break
            frontier = next_frontier
        return order

    @staticmethod
    def _find_node(cfg, target_addr: int):
        try:
            for node in cfg.graph.nodes():
                if getattr(node, "addr", None) == target_addr:
                    return node
        except Exception as e:
            log.debug(f"CFG node iteration failed: {e}")
        return None

    @staticmethod
    def _predecessors(cfg, node) -> List[Any]:
        try:
            return list(cfg.graph.predecessors(node))
        except Exception as e:
            log.debug(f"predecessors lookup failed for {node!r}: {e}")
            return []

    # ------------------------------------------------------------------ #
    # VEX dump
    # ------------------------------------------------------------------ #
    def _lift_to_vex(self, proj, block_addrs: List[int]) -> str:
        parts: List[str] = []
        for addr in block_addrs:
            try:
                block = proj.factory.block(addr)
                parts.append(f"// ---- block at {hex(addr)} ----")
                parts.append(str(block.vex))
            except Exception as e:
                log.debug(f"VEX lift failed at {hex(addr)}: {e}")
                parts.append(f"// ---- block at {hex(addr)} (lift failed) ----")
        return "\n".join(parts)

    # ------------------------------------------------------------------ #
    # external-call resolution
    # ------------------------------------------------------------------ #
    def _find_external_calls(self, proj, block_addrs: List[int]) -> List[ExternalCall]:
        calls: List[ExternalCall] = []
        for addr in block_addrs:
            try:
                block = proj.factory.block(addr)
                for insn in block.capstone.insns:
                    if insn.mnemonic not in ("call", "callq"):
                        continue
                    target_name = self._resolve_call_target(proj, insn.op_str)
                    if target_name:
                        calls.append(ExternalCall(addr=insn.address, target_name=target_name))
            except Exception as e:
                log.debug(f"external-call scan failed at {hex(addr)}: {e}")
        return calls

    @staticmethod
    def _resolve_call_target(proj, op_str: str) -> Optional[str]:
        try:
            cleaned = op_str.strip()
            if not cleaned:
                return None
            if not cleaned.startswith("0x"):
                # Could be a register or a symbol literal; let kb resolve symbols.
                try:
                    sym = proj.loader.find_symbol(cleaned)
                    if sym is not None:
                        return sym.name
                except Exception:
                    pass
                return None
            target_addr = int(cleaned, 16)
            try:
                if target_addr in proj.kb.functions:
                    return proj.kb.functions[target_addr].name
            except Exception:
                pass
            try:
                for plt_addr, name in proj.loader.main_object.plt.items():
                    if plt_addr == target_addr:
                        return name
            except Exception:
                pass
        except Exception as e:
            log.debug(f"resolve_call_target failed for {op_str!r}: {e}")
        return None

    # ------------------------------------------------------------------ #
    # Ghidra headless integration
    # ------------------------------------------------------------------ #
    def _try_ghidra(self, proj, block_addrs: List[int]) -> str:
        try:
            binary_path = getattr(proj, "filename", None)
            if not binary_path or not os.path.isfile(binary_path):
                log.debug("Ghidra: no binary file path on project")
                return ""
            headless = self._ghidra_headless_executable()
            if not headless or not os.path.isfile(headless):
                log.debug(f"Ghidra: analyzeHeadless not found at {headless}")
                return ""

            with tempfile.TemporaryDirectory(prefix="logictrap_ghidra_") as tmp:
                script_path = os.path.join(tmp, "decompile_slice.py")
                out_path = os.path.join(tmp, "out.c")
                project_dir = os.path.join(tmp, "ghidra_project")
                os.makedirs(project_dir, exist_ok=True)

                with open(script_path, "w", encoding="utf-8") as f:
                    f.write(self._ghidra_postscript())

                cmd = [
                    headless,
                    project_dir,
                    "LogictrapDecompile",
                    "-import", binary_path,
                    "-postScript", script_path, out_path, json.dumps([hex(a) for a in block_addrs]),
                    "-deleteProject",
                    "-overwrite",
                    "-readOnly",
                ]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=self.ghidra_timeout,
                    text=True,
                )
                if result.returncode != 0:
                    log.debug(f"Ghidra returned {result.returncode}: {result.stderr[:500]}")
                    return ""
                if not os.path.isfile(out_path):
                    log.debug("Ghidra: output file not produced")
                    return ""
                with open(out_path, "r", encoding="utf-8") as f:
                    return f.read()
        except subprocess.TimeoutExpired:
            log.debug("Ghidra invocation timed out")
            return ""
        except Exception as e:
            log.debug(f"Ghidra invocation failed: {e}")
            return ""

    def _ghidra_headless_executable(self) -> str:
        if not self.ghidra_install_dir:
            return ""
        support = Path(self.ghidra_install_dir) / "support"
        if os.name == "nt":
            return str(support / "analyzeHeadless.bat")
        return str(support / "analyzeHeadless")

    @staticmethod
    def _ghidra_postscript() -> str:
        """Ghidra post-script: decompile every function containing a slice
        block and concatenate the C output. Runs inside Ghidra's Jython."""
        return r"""
# logictrap-detector slice decompilation post-script
import json
import sys

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
if len(args) < 2:
    print("usage: decompile_slice.py <out_path> <addrs_json>")
    sys.exit(1)
out_path = args[0]
target_addrs = [int(a, 16) for a in json.loads(args[1])]

di = DecompInterface()
di.openProgram(currentProgram)

seen = set()
out_parts = []
addr_factory = currentProgram.getAddressFactory()
for raw in target_addrs:
    addr = addr_factory.getDefaultAddressSpace().getAddress(raw)
    func = getFunctionContaining(addr)
    if func is None:
        continue
    key = func.getEntryPoint().getOffset()
    if key in seen:
        continue
    seen.add(key)
    res = di.decompileFunction(func, 60, ConsoleTaskMonitor())
    if res is not None and res.getDecompiledFunction() is not None:
        out_parts.append("// ---- " + func.getName() + " @ " + str(func.getEntryPoint()) + " ----")
        out_parts.append(res.getDecompiledFunction().getC())

with open(out_path, "w") as f:
    f.write("\n".join(out_parts))
"""
