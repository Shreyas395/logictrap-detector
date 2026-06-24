import angr
import claripy
import sys
import os
import logging
import matplotlib.pyplot as plt
import time
import re
from typing import List, Tuple, Optional, Set, Dict, Any
from collections import defaultdict
import networkx as nx

from characterizer import Characterizer, CharacterizerError
from external_gates import ExternalGateCatalog
from gate_locator import LogicTrapAnalyzer, SinkFinder
from pipeline import characterize_gates
from scorer import SinkDistanceScorer
from slicer import GateSlicer

logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('claripy').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)
logging.getLogger('pyvex').setLevel(logging.CRITICAL)
log = logging.getLogger(__name__)


class EnhancedShellPayloadAnalyzer:  # Orchestrates payload discovery via symbolic execution and fuzzing
    def __init__(self, binary_path: str, max_input_size: int = 256):
        self.binary_path = binary_path  # path to target binary
        self.max_input_size = max_input_size  # maximum size for generated inputs
        self.proj = None  # angr Project instance placeholder
        self.cfg = None  # control-flow graph placeholder
        self.gate_catalog = ExternalGateCatalog()  # catalog of external function/syscall hooks
        self.sink_finder = SinkFinder()  # locates calls into dangerous primitives
        # Aliases below share state with the SinkFinder so existing call sites stay valid.
        self.dangerous_functions = self.sink_finder.dangerous_functions
        self.system_addrs = self.sink_finder.system_addrs  # addresses of system-like functions
        self.system_call_sites = self.sink_finder.system_call_sites  # addresses of detected system calls
        self.shell_syscalls = {11: 'execve', 59: 'execve', 57: 'fork', 58: 'vfork', 56: 'clone'}  # syscall numbers mapping
        self.input_functions = {'fgets', 'gets', 'scanf', 'fscanf', 'read', 'fread', 'getline',
                                'getdelim', 'fgetc', 'getchar', 'getc', '__isoc99_scanf'}  # functions reading user input
        self.shell_strings = []  # extracted shell-related strings
        self.found_solutions = []  # list of discovered payloads
        self.interesting_strings = []  # non-shell but noteworthy strings
        self.string_xrefs = {}  # cross-references for string usages
        self.symbolic_input = None  # symbolic variable for stdin
        self.system_reached = False  # flag indicating system hook reached
        self.solution_states = []  # saved solver states at system call
        self.logic_traps = []  # identified logic trap blocks
        self.payload_scores = []  # stealth scores per payload
        self.successful_payloads = {}  # mapping of addr to payload
        self.logic_analyzer = LogicTrapAnalyzer()  # logic trap detection helper
        self.symbolic_constraints = []  # list of applied input constraints
        self.gate_solutions = {}  # concrete values for gates per state
        self.gate_slicer = GateSlicer()  # backward slicer used by the pipeline
        self.gate_scorer = SinkDistanceScorer()  # sink-distance scorer
        self.gate_characterizer = self._build_characterizer()  # may be None if no LLM is configured
        self.gates = []  # gate-centric records emitted by characterize_gates

    @staticmethod
    def _build_characterizer():
        """Try to construct a Characterizer; return None if no backend is reachable.

        Letting the characterizer be None is the supported "I don't have an
        LLM set up" path — the rest of the pipeline still runs and produces
        slice/score output for each gate."""
        try:
            return Characterizer()
        except CharacterizerError as e:
            log.info(f"characterizer disabled: {e}")
            return None

    def load_binary(self) -> bool:
        try:
            self.proj = angr.Project(self.binary_path,
                                     auto_load_libs=False,
                                     load_options={'main_opts': {'base_addr': 0},
                                                   'auto_load_libs': False})  # load binary without libs
            print(f"[+] Loaded binary: {self.binary_path}")  # confirm load
            print(f"[+] Architecture: {self.proj.arch}")  # print CPU architecture
            print(f"[+] Entry point: {hex(self.proj.entry)}")  # print entry address
            discovered_gates = self.gate_catalog.catalog_binary_gates(self.proj)  # find external functions
            self.gate_catalog.create_symbolic_models()  # generate SimProcedures for gates
            self.setup_gate_hooks()  # install hooks for symbolic gates
            return True  # success
        except Exception as e:
            print(f"[-] Failed to load binary: {e}")  # report error
            return False  # failure

    def setup_gate_hooks(self):
        print("[+] Setting up symbolic gate hooks...")  # notify hooking start
        for gate_name, gate_addr in self.gate_catalog.discovered_gates.items():  # iterate discovered gates
            if gate_name in self.gate_catalog.symbolic_models:
                try:
                    self.proj.hook_symbol(gate_name, self.gate_catalog.symbolic_models[gate_name]())  # hook by name
                    print(f"    Hooked {gate_name} symbol")
                except Exception as e:
                    log.debug(f"hook_symbol failed for {gate_name}: {e}")
                try:
                    self.proj.hook(gate_addr, self.gate_catalog.symbolic_models[gate_name]())  # hook by address
                    print(f"    Hooked {gate_name} at {hex(gate_addr)}")
                except Exception as e:
                    log.debug(f"hook by addr failed for {gate_name} at {hex(gate_addr)}: {e}")

    def build_cfg(self) -> bool:
        print("[+] Building comprehensive CFG...")
        try:
            self.cfg = self.proj.analyses.CFGFast(
                normalize=True,
                data_references=True,
                force_complete_scan=True,
                cross_references=True,
                function_prologues=True,
                resolve_indirect_jumps=True
            )
            print(f"[+] Comprehensive CFG built with {len(self.cfg.graph.nodes)} nodes")

            # Export mini CFG to image
            os.makedirs("output", exist_ok=True)
            cfg_image_path = os.path.join("output", "partial_cfg.png")
            subgraph = self.cfg.graph.subgraph(list(self.cfg.graph.nodes)[:10])  # grab first 10 nodes
            pos = nx.spring_layout(subgraph)
            plt.figure(figsize=(10, 8))
            nx.draw(subgraph, pos, with_labels=True, node_color='lightblue', edge_color='gray', node_size=500)
            plt.title("Partial CFG (First 10 Nodes)")
            plt.savefig(cfg_image_path, dpi=300)
            print(f"[+] Saved partial CFG image as {cfg_image_path}")

            return True
        except Exception as e:
            print(f"[-] CFG construction failed: {e}")
            return False

    def find_shell_strings(self) -> List[Tuple[int, str]]:
        print("[+] Finding shell-related strings...")  # notify string scan
        shell_patterns = [
            r'/bin/sh', r'/bin/bash', r'/bin/zsh', r'sh\s*$', r'bash\s*$',
            r'system\s*\(', r'exec[lv]', r'cmd\.exe', r'powershell', r'shell',
            r'whoami', r'id\s*$', r'cat\s+', r'ls\s+', r'/usr/bin/', r'/sbin/',
            r'nc\s+', r'netcat', r'flag', r'secret', r'password', r'admin', r'root'
        ]  # regexes for shell indicators
        strings_found = []  # collect matches
        try:
            for section in self.proj.loader.main_object.sections:  # iterate readable sections
                if section.is_readable:
                    try:
                        data = self.proj.loader.memory.load(section.vaddr, section.memsize)  # raw bytes
                        current_string = ""  # buffer for ascii chars
                        current_addr = section.vaddr  # base address
                        for i, byte in enumerate(data):
                            if 32 <= byte <= 126:
                                current_string += chr(byte)  # accumulate printable
                            elif byte == 0 and len(current_string) > 0:
                                for pattern in shell_patterns:
                                    if re.search(pattern, current_string, re.IGNORECASE):
                                        addr = current_addr + i - len(current_string)
                                        strings_found.append((addr, current_string))  # record shell string
                                        self.shell_strings.append((addr, current_string))
                                        print(f"    Found shell string at {hex(addr)}: '{current_string}'")
                                        break
                                if len(current_string) > 3:
                                    addr = current_addr + i - len(current_string)
                                    self.interesting_strings.append((addr, current_string))  # record interesting non-shell
                                current_string = ""  # reset buffer
                            else:
                                current_string = ""  # reset on non-printable
                    except Exception:
                        continue
        except Exception as e:
            print(f"[-] Error finding strings: {e}")  # catch high-level failures
        return strings_found  # return all found shell strings

    def create_enhanced_system_hook(self):
        analyzer = self  # capture self for inner class closure
        
        class EnhancedSystemHook(angr.SimProcedure):
            def run(self, command_ptr=None, *args, **kwargs):
                analyzer.system_reached = True
                self.state.globals['reached_system'] = True
                self.state.globals['system_addr'] = self.state.addr
                
                # Initialize variables that were missing
                stealth_score = 5  # Default stealth score
                gate_solutions = {}  # Initialize gate solutions dict
                
                # Try to find solutions with current constraints
                solutions_found = []
                
                try:
                    if 'symbolic_input' in self.state.globals:
                        sym_input = self.state.globals['symbolic_input']
                        
                        # First try with current constraints
                        if self.state.solver.symbolic(sym_input):
                            try:
                                possible_vals = self.state.solver.eval_upto(sym_input, 10)
                            except Exception:
                                possible_vals = []
                            
                            # If no solutions, try constraint relaxation
                            if not possible_vals:
                                print("[!] No solutions with current constraints, relaxing...")
                                try:
                                    relaxed_state = self.state.copy()
                                    
                                    # Remove some constraints and try again
                                    constraint_count = len(relaxed_state.solver.constraints)
                                    if constraint_count > 10:
                                        # Remove last 25% of constraints
                                        remove_count = constraint_count // 4
                                        for _ in range(remove_count):
                                            if relaxed_state.solver.constraints:
                                                relaxed_state.solver.constraints.pop()
                                    
                                    possible_vals = relaxed_state.solver.eval_upto(sym_input, 10)
                                except Exception:
                                    possible_vals = []
                            
                            # Collect gate solutions from current state
                            for gate_name in analyzer.gate_catalog.discovered_gates:
                                gate_key = f'{gate_name}_sym'
                                if gate_key in self.state.globals:
                                    try:
                                        gate_val = self.state.solver.eval(self.state.globals[gate_key])
                                        gate_solutions[gate_name] = gate_val
                                        stealth_score += 1
                                    except Exception:
                                        pass
                            
                            # Process possible values
                            for val in possible_vals:
                                try:
                                    if val != 0:
                                        # Handle potential overflow for large values
                                        try:
                                            bit_length = val.bit_length()
                                            if bit_length > 0:
                                                byte_length = (bit_length + 7) // 8
                                                # Limit byte length to prevent memory issues
                                                if byte_length > 1024:
                                                    byte_length = 1024
                                                val_bytes = val.to_bytes(byte_length, 'big')
                                            else:
                                                val_bytes = b'\x00'
                                        except (OverflowError, ValueError):
                                            # Handle large integers by truncating
                                            val_bytes = (val & 0xFFFFFFFF).to_bytes(4, 'big')
                                        
                                        val_str = analyzer.clean_solution(val_bytes)
                                        if val_str and val_str.strip():
                                            analyzer.found_solutions.append({
                                                'payload': val_str.strip(),
                                                'stealth_score': stealth_score,
                                                'addr': hex(self.state.addr),
                                                'method': 'enhanced_symbolic',
                                                'gates': gate_solutions.copy()
                                            })
                                            print(f"    Enhanced symbolic input: '{val_str.strip()}'")
                                except Exception as e:
                                    print(f"    Error processing value {val}: {e}")
                                    continue
                                    
                except Exception as e:
                    print(f"[!] Enhanced system hook error: {e}")
                
                return 0  # override return to avoid real system execution
        
        return EnhancedSystemHook

    def setup_hooks(self, system_calls: List[Tuple[int, str]]):
        hook_class = self.create_enhanced_system_hook()  # get hook procedure
        print("[+] Setting up enhanced system hooks...")
        for func_name in self.dangerous_functions:
            try:
                self.proj.hook_symbol(func_name, hook_class())  # hook by symbol
                print(f"    Hooked {func_name} symbol")
            except Exception as e:
                log.debug(f"hook_symbol failed for {func_name}: {e}")
        hooked_addrs = set()  # track addresses already hooked
        for addr, call_type in system_calls:
            if addr not in hooked_addrs:
                try:
                    self.proj.hook(addr, hook_class())  # hook each call site
                    hooked_addrs.add(addr)
                    print(f"    Hooked {call_type} at {hex(addr)}")
                except Exception as e:
                    log.debug(f"hook of {call_type} at {hex(addr)} failed: {e}")
        for system_addr in self.system_addrs:
            if system_addr not in hooked_addrs:
                try:
                    self.proj.hook(system_addr, hook_class())  # hook direct system functions
                    hooked_addrs.add(system_addr)
                    print(f"    Hooked system function at {hex(system_addr)}")
                except Exception as e:
                    log.debug(f"hook of system function at {hex(system_addr)} failed: {e}")

    def add_primary_input_constraints(self, state):
        print("[+] Adding minimal input constraints...")
        if 'symbolic_input' in state.globals:
            sym_input = state.globals['symbolic_input']
            input_size = sym_input.size() // 8
            
            # Allow null terminators and common exploit characters
            for i in range(min(input_size, 16)):  # Reduced constraint range
                byte_val = sym_input.get_byte(i)
                # Allow null bytes, newlines, tabs, and printable ASCII
                state.solver.add(claripy.Or(
                    byte_val == 0,  # null terminator
                    byte_val == 10,  # newline
                    byte_val == 9,   # tab
                    claripy.And(byte_val >= 32, byte_val <= 126)  # printable
                ))
                self.symbolic_constraints.append(f"byte[{i}] flexible")
            
            # Removed forced numeric constraint on first two bytes

    def guided_symbolic_execution(self, priority_addrs: List[int], input_size: int = 32) -> bool:
        print(f"[+] Running enhanced guided symbolic execution (input size: {input_size})...")
        class EnhancedLogicTrapExplorer(angr.exploration_techniques.ExplorationTechnique):
            def __init__(self, trap_addrs, gate_addrs, analyzer):
                super().__init__()
                self.trap_addrs = set(trap_addrs)
                self.gate_addrs = set(gate_addrs)
                self.analyzer = analyzer
                self.visited_blocks = set()
                self.priority_states = []
                
            def step(self, simgr, stash='active', **kwargs):
                # Prioritize states based on coverage and proximity to targets
                enhanced_states = []
                normal_states = []
                
                for state in simgr.stashes.get(stash, []):
                    priority_score = 0
                    
                    # Higher priority for new basic blocks
                    if state.addr not in self.visited_blocks:
                        priority_score += 5
                        self.visited_blocks.add(state.addr)
                    
                    # Higher priority near traps or gates
                    is_near_trap = any(abs(state.addr - trap_addr) < 100 for trap_addr in self.trap_addrs)
                    is_near_gate = any(abs(state.addr - gate_addr) < 100 for gate_addr in self.gate_addrs)
                    
                    if is_near_trap:
                        priority_score += 10
                    if is_near_gate:
                        priority_score += 8
                        
                    # Lower priority for states with too many constraints
                    if len(state.solver.constraints) > 50:
                        priority_score -= 3
                        
                    if priority_score > 5:
                        enhanced_states.append((priority_score, state))
                    else:
                        normal_states.append(state)
                
                # Sort by priority and keep reasonable number
                enhanced_states.sort(key=lambda x: x[0], reverse=True)
                final_states = [state for _, state in enhanced_states[:8]] + normal_states[:4]
                
                simgr.stashes[stash] = final_states
                return simgr.step(stash=stash, **kwargs)
        
        # Create multiple symbolic inputs for different scenarios
        self.symbolic_input = claripy.BVS('user_input', input_size * 8)
        
        initial_state = self.proj.factory.entry_state(
            stdin=self.symbolic_input,
            add_options={
                angr.options.LAZY_SOLVES,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOLIC_WRITE_ADDRESSES  # Enable symbolic write tracking
            },
            remove_options={angr.options.SUPPORT_FLOATING_POINT}
        )
        
        initial_state.globals['symbolic_input'] = self.symbolic_input
        self.add_primary_input_constraints(initial_state)
        
        simgr = self.proj.factory.simgr(initial_state)
        
        # Use enhanced exploration technique
        trap_addrs = [addr for addr, _ in self.logic_traps]
        gate_addrs = list(self.gate_catalog.discovered_gates.values())
        simgr.use_technique(EnhancedLogicTrapExplorer(trap_addrs, gate_addrs, self))
        
        timeout_seconds = 60
        explore_start = time.monotonic()

        def time_limit_step(sm):
            if time.monotonic() - explore_start > timeout_seconds:
                sm.move(from_stash='active', to_stash='deadended')
            return sm

        try:
            simgr.explore(
                find=lambda s: s.globals.get('reached_system', False),
                avoid=lambda s: s.addr == 0 or len(s.solver.constraints) > 100,
                num_find=50,
                step_func=time_limit_step
            )
            if time.monotonic() - explore_start > timeout_seconds:
                print("[!] Symbolic execution hit 60s timeout, using found states")
        except Exception as e:
            print(f"[-] Symbolic execution failed: {e}")
            return False

        print(f"[+] Exploration complete: {len(simgr.found)} solutions found")
        for found_state in simgr.found:
            try:
                if 'symbolic_input' in found_state.globals:
                    sym_input = found_state.globals['symbolic_input']
                    possible_inputs = found_state.solver.eval_upto(sym_input, 10)
                    for input_val in possible_inputs:
                        try:
                            input_bytes = input_val.to_bytes((input_val.bit_length() + 7) // 8, 'big')
                            payload_str = self.clean_solution(input_bytes)
                            if payload_str and len(payload_str.strip()) > 0:
                                stealth_score = 5  # base guided score
                                for trap_addr, trap_info in self.logic_traps:
                                    if abs(found_state.addr - trap_addr) < 100:
                                        stealth_score += trap_info['score']
                                gate_data = {}
                                for gate_name in self.gate_catalog.discovered_gates:
                                    gate_key = f'{gate_name}_sym'
                                    if gate_key in found_state.globals:
                                        try:
                                            gate_val = found_state.solver.eval(found_state.globals[gate_key])
                                            gate_data[gate_name] = gate_val
                                            stealth_score += 1
                                        except Exception as e:
                                            log.debug(f"gate eval failed for {gate_name}: {e}")
                                self.found_solutions.append({
                                    'payload': payload_str.strip(),
                                    'stealth_score': stealth_score,
                                    'addr': hex(found_state.addr),
                                    'method': 'guided_symbolic',
                                    'gates': gate_data,
                                    'constraints': len(found_state.solver.constraints)
                                })
                                print(f"    Found payload: '{payload_str.strip()}' (score: {stealth_score})")
                        except Exception as e:
                            log.debug(f"payload eval failed: {e}")
                            continue
            except Exception as e:
                print(f"    Error processing found state: {e}")
                continue
        return len(simgr.found) > 0  # return whether any found

    def clean_solution(self, solution_bytes: bytes) -> str:
        """Clean and validate solution bytes with endianness handling"""
        try:
            # Try both big-endian and little-endian interpretations
            for endian in ['big', 'little']:
                try:
                    if isinstance(solution_bytes, int):
                        # Convert int to bytes in both endiannesses
                        byte_len = (solution_bytes.bit_length() + 7) // 8
                        if endian == 'big':
                            test_bytes = solution_bytes.to_bytes(byte_len, 'big')
                        else:
                            test_bytes = solution_bytes.to_bytes(byte_len, 'little')
                    else:
                        test_bytes = solution_bytes
                    
                    # Try multiple encodings
                    for encoding in ['utf-8', 'ascii', 'latin-1']:
                        try:
                            decoded = test_bytes.decode(encoding)
                            # Keep null terminators and common exploit chars
                            cleaned = ''.join(c for c in decoded if ord(c) == 0 or ord(c) == 10 or ord(c) == 9 or 32 <= ord(c) <= 126)
                            if len(cleaned) > 0:
                                return cleaned
                        except Exception:
                            continue
                except Exception:
                    continue
            return solution_bytes.hex()  # fallback to hex
        except Exception:
            return ""

    def fuzzing_based_discovery(self, input_size: int = 64) -> List[str]:
        """Enhanced fuzzing with gate-aware payloads"""
        print(f"[+] Running enhanced fuzzing (input size: {input_size})...")
        base_payloads = [
            b"A" * 32, b"1234567890", b"admin", b"root", b"password", b"shell",
            b"/bin/sh", b"system", b"exec", b"0", b"1", b"-1", b"999999",
            b"secret", b"flag", b"debug", b"test"
        ]  # initial guess inputs
        if any(g in self.gate_catalog.discovered_gates for g in self.gate_catalog.randomness_gates):
            base_payloads.extend([b"random", b"seed", b"entropy"])  # include randomness terms
        if any(g in self.gate_catalog.discovered_gates for g in self.gate_catalog.env_gates):
            base_payloads.extend([b"PATH", b"HOME", b"USER", b"SHELL"])  # include env terms
        if any(g in self.gate_catalog.discovered_gates for g in self.gate_catalog.time_gates):
            base_payloads.extend([b"1970", b"2024", b"time", b"date"])  # include time terms
        if any(g in self.gate_catalog.discovered_gates for g in self.gate_catalog.uid_gates):
            base_payloads.extend([b"0", b"1000", b"uid", b"gid"])  # include UID terms

        fuzzing_results = []
        for payload in base_payloads:
            try:
                if len(payload) < input_size:
                    payload = payload + b"\x00" * (input_size - len(payload))  # pad to size
                else:
                    payload = payload[:input_size]  # truncate if too long
                concrete_input = claripy.BVV(int.from_bytes(payload, 'big'), input_size * 8)  # concrete BVV
                test_state = self.proj.factory.entry_state(
                    stdin=concrete_input, add_options={angr.options.LAZY_SOLVES}
                )  # initial state for fuzz case
                test_state.globals['symbolic_input'] = concrete_input
                simgr = self.proj.factory.simgr(test_state)
                try:
                    simgr.run(n=100)  # limit steps
                    for stash_name, states in simgr.stashes.items():
                        for state in states:
                            if state.globals.get('reached_system', False):  # check hook flag
                                payload_str = self.clean_solution(payload)
                                if payload_str:
                                    fuzzing_results.append(payload_str)  # record successful fuzz
                                    print(f"    Fuzzing hit: '{payload_str}'")
                                break
                except Exception as e:
                    log.debug(f"fuzz simgr.run failed: {e}")
                    continue
            except Exception as e:
                log.debug(f"fuzz payload setup failed: {e}")
                continue
        return fuzzing_results  # return all fuzz hits

    def analyze_enhanced(self) -> Dict[str, Any]:
        """Main analysis function with enhanced capabilities"""
        print("="*60)
        print("ENHANCED SHELL PAYLOAD ANALYZER")
        print("="*60)
        if not self.load_binary():
            return {'error': 'Failed to load binary'}  # abort on load failure
        if not self.build_cfg():
            return {'error': 'Failed to build CFG'}  # abort on CFG failure
        shell_strings = self.find_shell_strings()  # gather strings
        system_calls = self.sink_finder.find(self.proj)  # gather calls
        gate_addrs = set(self.gate_catalog.discovered_gates.values())
        self.logic_traps = self.logic_analyzer.find_logic_traps(self.proj, self.cfg, gate_addrs)  # detect traps
        self.setup_hooks(system_calls)  # install all hooks
        found_any = False
        if self.guided_symbolic_execution(list(gate_addrs), 32):
            found_any = True  # mark if symbolic found any
        fuzz_results = self.fuzzing_based_discovery(64)
        for fuzz_payload in fuzz_results:
            self.found_solutions.append({
                'payload': fuzz_payload,
                'stealth_score': 3,
                'addr': 'fuzzing',
                'method': 'enhanced_fuzzing',
                'gates': {},
                'constraints': 0
            })
            found_any = True
        for size in [16, 48, 96, 128]:
            if len(self.found_solutions) < 10:
                try:
                    if self.guided_symbolic_execution(list(gate_addrs), size):
                        found_any = True
                except Exception as e:
                    log.debug(f"guided_symbolic_execution failed at input_size={size}: {e}")
                    continue
        # New gate-centric pipeline: slice + score + (optional) characterize
        # each trap. Behaviour-additive — the legacy fields above keep working.
        self.gates = characterize_gates(
            proj=self.proj,
            cfg=self.cfg,
            logic_traps=self.logic_traps,
            sink_addrs=self.system_addrs,
            slicer=self.gate_slicer,
            scorer=self.gate_scorer,
            characterizer=self.gate_characterizer,
        )
        results = {
            'binary_path': self.binary_path,
            'discovered_gates': dict(self.gate_catalog.discovered_gates),
            'shell_strings': shell_strings,
            'system_calls': system_calls,
            'logic_traps': [(hex(addr), info) for addr, info in self.logic_traps],
            'gates': self.gates,
            'solutions': self.found_solutions,
            'gate_solutions': self.gate_solutions,
            'analysis_success': found_any,
            'total_solutions': len(self.found_solutions),
            'highest_stealth_score': max([s.get('stealth_score', 0) for s in self.found_solutions], default=0)
        }  # compile final report
        return results

    def print_enhanced_results(self, results: Dict[str, Any]):
        """Print enhanced analysis results"""
        print("\n" + "="*60)
        print("ENHANCED ANALYSIS RESULTS")
        print("="*60)
        print(f"\n[+] Binary: {results['binary_path']}")
        print(f"[+] Analysis Success: {results['analysis_success']}")
        print(f"[+] Total Solutions Found: {results['total_solutions']}")
        print(f"[+] Highest Stealth Score: {results['highest_stealth_score']}")
        if results['discovered_gates']:
            print(f"\n[+] External Gates Discovered ({len(results['discovered_gates'])}):")
            for gate_name, gate_addr in results['discovered_gates'].items():
                print(f"    {gate_name}: {hex(gate_addr)}")  # list each gate
        if results['logic_traps']:
            print(f"\n[+] Logic Traps Found ({len(results['logic_traps'])}):")
            for trap_addr, trap_info in results['logic_traps']:
                print(f"    {trap_addr}: score={trap_info['score']}, ops={len(trap_info['operations'])}")
        if results['solutions']:
            print(f"\n[+] PAYLOAD SOLUTIONS ({len(results['solutions'])}):")
            sorted_solutions = sorted(results['solutions'], key=lambda x: x.get('stealth_score', 0), reverse=True)
            for i, solution in enumerate(sorted_solutions, 1):
                print(f"\n    Solution #{i}:")
                print(f"      Payload: '{solution['payload']}'")
                print(f"      Stealth Score: {solution.get('stealth_score', 0)}")
                print(f"      Method: {solution.get('method', 'unknown')}")
                print(f"      Address: {solution.get('addr', 'unknown')}")
                if solution.get('gates'):
                    print(f"      Gate Values:")
                    for gate_name, gate_val in solution['gates'].items():
                        print(f"        {gate_name}: {gate_val}")  # detailed gate outputs
        if not results['analysis_success']:
            print("\n[-] No solutions found. Try:")
            print("    - Different input sizes")
            print("    - Manual analysis of discovered gates")
            print("    - Extended symbolic execution")  # suggestions on failure


def main():
    if len(sys.argv) != 2:
        print("Usage: python enhanced_analyzer.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    if not os.path.exists(binary_path):
        print(f"Error: Binary file '{binary_path}' not found")
        sys.exit(1)
    
    analyzer = EnhancedShellPayloadAnalyzer(binary_path, max_input_size=256)
    
    start_time = time.time()
    results = analyzer.analyze_enhanced()
    end_time = time.time()
    
    analyzer.print_enhanced_results(results)
    
    print(f"\n[+] Analysis completed in {end_time - start_time:.2f} seconds")
    
    


if __name__ == "__main__":
    main()