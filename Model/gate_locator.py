"""Locates candidate "logic-trap" gates inside a binary.

A gate, in this project's terminology, is a basic block whose predicate
is dense with bitwise / arithmetic / comparison ops and (optionally)
calls into known external dependencies. Gates of interest sit on a CFG
path toward a dangerous sink (``system``, ``execve``, etc.) and act as
the dormant condition hiding a payload.

Two main entry points:

  - ``SinkFinder``: walks an angr ``Project`` and collects addresses of
    dangerous primitive calls (the sinks).
  - ``LogicTrapAnalyzer``: scores each basic block by instruction
    complexity and flags blocks likely to be acting as predicates.
"""
import logging
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


DEFAULT_DANGEROUS_FUNCTIONS: FrozenSet[str] = frozenset({
    'system', 'execve', 'execvp', 'execl', 'execlp', 'execle', 'execv',
    'posix_spawn', 'posix_spawnp', 'popen', 'sh', 'bash', 'zsh',
    'fork', 'vfork', 'clone', 'waitpid', 'wait', 'wait3', 'wait4',
})

DEFAULT_CALL_MNEMONICS: FrozenSet[str] = frozenset({'call', 'callq'})
DEFAULT_DIRECT_SYSCALL_MNEMONICS: FrozenSet[str] = frozenset({'syscall', 'int', 'sysenter'})


class SinkFinder:
    """Locates calls into dangerous shell-execution primitives."""

    def __init__(
        self,
        dangerous_functions: Optional[Iterable[str]] = None,
        call_mnemonics: Optional[Iterable[str]] = None,
        direct_syscall_mnemonics: Optional[Iterable[str]] = None,
    ):
        self.dangerous_functions: Set[str] = (
            set(dangerous_functions) if dangerous_functions is not None
            else set(DEFAULT_DANGEROUS_FUNCTIONS)
        )
        self.call_mnemonics: Set[str] = (
            set(call_mnemonics) if call_mnemonics is not None
            else set(DEFAULT_CALL_MNEMONICS)
        )
        self.direct_syscall_mnemonics: Set[str] = (
            set(direct_syscall_mnemonics) if direct_syscall_mnemonics is not None
            else set(DEFAULT_DIRECT_SYSCALL_MNEMONICS)
        )
        self.system_addrs: Set[int] = set()
        self.system_call_sites: List[int] = []

    def find(self, proj) -> List[Tuple[int, str]]:
        """Return a list of ``(address, kind)`` for every dangerous call site."""
        system_calls: List[Tuple[int, str]] = []
        print("[+] Enhanced system call detection...")

        # 1) Resolve each dangerous function's address via three angr surfaces.
        for func_name in self.dangerous_functions:
            try:
                if func_name in proj.kb.functions:
                    func = proj.kb.functions[func_name]
                    self.system_addrs.add(func.addr)
                    print(f"    {func_name} function found at {hex(func.addr)}")
            except Exception as e:
                log.debug(f"kb.functions lookup failed for {func_name}: {e}")
            try:
                for addr, name in proj.loader.main_object.plt.items():
                    if name == func_name:
                        self.system_addrs.add(addr)
                        print(f"    {func_name} PLT entry at {hex(addr)}")
            except Exception as e:
                log.debug(f"PLT scan failed for {func_name}: {e}")
            try:
                symbol = proj.loader.find_symbol(func_name)
                if symbol:
                    self.system_addrs.add(symbol.rebased_addr)
                    print(f"    {func_name} symbol at {hex(symbol.rebased_addr)}")
            except Exception as e:
                log.debug(f"find_symbol failed for {func_name}: {e}")

        # 2) Disassembly sweep for direct call/syscall sites.
        try:
            all_functions = list(proj.kb.functions.values())
            for func in all_functions:
                try:
                    for block_addr in func.block_addrs:
                        try:
                            block = proj.factory.block(block_addr)
                            for insn in block.capstone.insns:
                                if insn.mnemonic in self.call_mnemonics:
                                    for dangerous_func in self.dangerous_functions:
                                        if dangerous_func in insn.op_str.lower():
                                            system_calls.append((insn.address, f'{dangerous_func}_call'))
                                            self.system_call_sites.append(insn.address)
                                            print(f"    FOUND: {dangerous_func} call at {hex(insn.address)}")
                                            break
                                elif insn.mnemonic in self.direct_syscall_mnemonics:
                                    system_calls.append((insn.address, 'syscall'))
                                    self.system_call_sites.append(insn.address)
                                    print(f"    FOUND: syscall at {hex(insn.address)}")
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception as e:
            print(f"    Error scanning for system calls: {e}")
        return system_calls


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
