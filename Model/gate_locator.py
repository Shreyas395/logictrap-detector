"""Locates candidate "logic-trap" gates inside a binary.

A gate, in this project's terminology, is a basic block whose predicate is
dense with bitwise / arithmetic / comparison ops and (optionally) calls into
known external dependencies. Gates of interest sit on a CFG path toward a
dangerous sink (system, execve, etc.) and act as the dormant condition
hiding a payload.

Week 2 scope: extracted LogicTrapAnalyzer from the original orchestrator.
Weeks 4+: the slicer (slicer.py) will consume the gates found here and
extract their backward-slice for LLM characterization.
"""
import logging
from typing import Any, Dict, List, Set, Tuple

log = logging.getLogger(__name__)


class LogicTrapAnalyzer:
    def __init__(self):
        self.complex_operations = {'xor', 'and', 'or', 'not', 'shl', 'shr', 'sar', 'mul', 'imul', 'div', 'idiv', 'mod'}
        self.comparison_ops = {'cmp', 'test', 'cmpl', 'testl', 'cmpq', 'testq'}
        self.symbolic_ops = {'call', 'callq'}

    def analyze_block_complexity(self, proj, block_addr: int, gate_addrs: Set[int]) -> Dict[str, Any]:
        try:
            block = proj.factory.block(block_addr)
            complexity_score = 0
            operations = []
            comparisons = []
            gate_calls = []
            for insn in block.capstone.insns:
                mnemonic = insn.mnemonic.lower()
                if mnemonic in self.complex_operations:
                    complexity_score += 2
                    operations.append((insn.address, mnemonic, insn.op_str))
                if mnemonic in self.comparison_ops:
                    complexity_score += 1
                    comparisons.append((insn.address, mnemonic, insn.op_str))
                if mnemonic.startswith('j') and mnemonic != 'jmp':
                    complexity_score += 1
                if mnemonic in self.symbolic_ops:
                    try:
                        target_addr = int(insn.op_str.split('x')[1], 16) if 'x' in insn.op_str else 0
                        if target_addr in gate_addrs:
                            complexity_score += 3
                            gate_calls.append((insn.address, mnemonic, insn.op_str))
                    except Exception as e:
                        log.debug(f"call-target parse failed at {hex(insn.address)}: {e}")
            return {
                'score': complexity_score,
                'operations': operations,
                'comparisons': comparisons,
                'gate_calls': gate_calls,
                'is_trap': complexity_score >= 3,
            }
        except Exception as e:
            log.debug(f"block analysis failed at {hex(block_addr)}: {e}")
            return {'score': 0, 'operations': [], 'comparisons': [], 'gate_calls': [], 'is_trap': False}

    def find_logic_traps(self, proj, cfg, gate_addrs: Set[int]) -> List[Tuple[int, Dict[str, Any]]]:
        traps = []
        print("[+] Re-analyzing logic complexity with gates...")
        for node in cfg.graph.nodes():
            if hasattr(node, 'addr'):
                analysis = self.analyze_block_complexity(proj, node.addr, gate_addrs)
                if analysis['is_trap']:
                    traps.append((node.addr, analysis))
                    print(f"    Enhanced trap at {hex(node.addr)}: score={analysis['score']}")
                    if analysis['gate_calls']:
                        print(f"      Gate calls: {len(analysis['gate_calls'])}")
        return traps
