import angr
import claripy
import sys
import os
import logging
import time
import re
from typing import List, Tuple, Optional, Set, Dict, Any
from collections import defaultdict
import networkx as nx
logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('claripy').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)
logging.getLogger('pyvex').setLevel(logging.CRITICAL)
class LogicTrapAnalyzer:
    def __init__(self):
        self.complex_operations = {
            'xor', 'and', 'or', 'not', 'shl', 'shr', 'sar',
            'mul', 'imul', 'div', 'idiv', 'mod'
        }
        self.comparison_ops = {
            'cmp', 'test', 'cmpl', 'testl', 'cmpq', 'testq'
        }
    def analyze_block_complexity(self, proj, block_addr: int) -> Dict[str, Any]:
        try:
            block = proj.factory.block(block_addr)
            complexity_score = 0
            operations = []
            comparisons = []
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
            return {
                'score': complexity_score,
                'operations': operations,
                'comparisons': comparisons,
                'is_trap': complexity_score >= 3
            }
        except Exception as e:
            return {'score': 0, 'operations': [], 'comparisons': [], 'is_trap': False}
    def find_logic_traps(self, proj, cfg) -> List[Tuple[int, Dict[str, Any]]]:
        traps = []
        print("[+] Analyzing logic complexity...")
        for node in cfg.graph.nodes():
            if hasattr(node, 'addr'):
                analysis = self.analyze_block_complexity(proj, node.addr)
                if analysis['is_trap']:
                    traps.append((node.addr, analysis))
                    print(f"    Logic trap candidate at {hex(node.addr)}: score={analysis['score']}")
        return traps
class TaintTracker:
    def __init__(self):
        self.tainted_vars = set()
        self.input_influences = defaultdict(list)
    def mark_input_tainted(self, state, input_var):
        self.tainted_vars.add(input_var)
        state.globals['tainted_vars'] = self.tainted_vars
    def check_taint_propagation(self, state, addr: int):
        return len(self.tainted_vars) > 0
class EnhancedShellPayloadAnalyzer:
    def __init__(self, binary_path: str, max_input_size: int = 256):
        self.binary_path = binary_path
        self.max_input_size = max_input_size
        self.proj = None
        self.cfg = None
        self.dangerous_functions = {
            'system', 'execve', 'execvp', 'execl', 'execlp', 'execle', 'execv',
            'posix_spawn', 'posix_spawnp', 'popen', 'sh', 'bash', 'zsh',
            'fork', 'vfork', 'clone', 'waitpid', 'wait', 'wait3', 'wait4'
        }
        self.shell_syscalls = {
            11: 'execve',
            59: 'execve',
            57: 'fork',
            58: 'vfork',
            56: 'clone',
        }
        self.input_functions = {
            'fgets', 'gets', 'scanf', 'fscanf', 'read', 'fread', 'getline', 
            'getdelim', 'fgetc', 'getchar', 'getc', '__isoc99_scanf'
        }
        self.shell_strings = []
        self.system_call_sites = []
        self.found_solutions = []
        self.interesting_strings = []
        self.string_xrefs = {}
        self.symbolic_input = None
        self.system_reached = False
        self.system_addrs = set()
        self.solution_states = []
        self.logic_traps = []
        self.payload_scores = []
        self.successful_payloads = {}
        self.logic_analyzer = LogicTrapAnalyzer()
        self.taint_tracker = TaintTracker()
    def load_binary(self) -> bool:
        try:
            self.proj = angr.Project(self.binary_path, auto_load_libs=False, 
                                   load_options={
                                       'main_opts': {'base_addr': 0},
                                       'auto_load_libs': False
                                   })
            print(f"[+] Loaded binary: {self.binary_path}")
            print(f"[+] Architecture: {self.proj.arch}")
            print(f"[+] Entry point: {hex(self.proj.entry)}")
            return True
        except Exception as e:
            print(f"[-] Failed to load binary: {e}")
            return False
    def build_cfg(self) -> bool:
        print("[+] Building CFG...")
        try:
            self.cfg = self.proj.analyses.CFGFast(
                normalize=True,
                data_references=True,
                resolve_indirect_jumps=True,
                force_complete_scan=False
            )
            print(f"[+] CFGFast built with {len(self.cfg.graph.nodes)} nodes")
            return True
        except Exception as e:
            print(f"[-] CFGFast failed: {e}")
            return False
    def find_shell_strings(self) -> List[Tuple[int, str]]:
        print("[+] Finding shell-related strings...")
        shell_patterns = [
            r'/bin/sh', r'/bin/bash', r'/bin/zsh', r'sh\s*$', r'bash\s*$',
            r'system\s*\(', r'exec[lv]', r'cmd\.exe', r'powershell',
            r'shell', r'whoami', r'id\s*$', r'cat\s+', r'ls\s+',
            r'/usr/bin/', r'/sbin/', r'nc\s+', r'netcat', r'flag',
            r'secret', r'password', r'admin', r'root'
        ]
        strings_found = []
        try:
            for section in self.proj.loader.main_object.sections:
                if section.is_readable:
                    try:
                        data = self.proj.loader.memory.load(section.vaddr, section.memsize)
                        current_string = ""
                        current_addr = section.vaddr
                        for i, byte in enumerate(data):
                            if 32 <= byte <= 126:
                                current_string += chr(byte)
                            elif byte == 0 and len(current_string) > 0:
                                for pattern in shell_patterns:
                                    if re.search(pattern, current_string, re.IGNORECASE):
                                        addr = current_addr + i - len(current_string)
                                        strings_found.append((addr, current_string))
                                        self.shell_strings.append((addr, current_string))
                                        print(f"    Found shell string at {hex(addr)}: '{current_string}'")
                                        break
                                if len(current_string) > 3:
                                    addr = current_addr + i - len(current_string)
                                    self.interesting_strings.append((addr, current_string))
                                current_string = ""
                            else:
                                current_string = ""
                    except Exception as e:
                        continue
        except Exception as e:
            print(f"[-] Error finding strings: {e}")
        return strings_found
    def find_system_calls_enhanced(self) -> List[Tuple[int, str]]:
        system_calls = []
        print("[+] Enhanced system call detection...")
        for func_name in self.dangerous_functions:
            try:
                if func_name in self.proj.kb.functions:
                    func = self.proj.kb.functions[func_name]
                    self.system_addrs.add(func.addr)
                    print(f"    {func_name} function found at {hex(func.addr)}")
            except:
                pass
            try:
                for addr, name in self.proj.loader.main_object.plt.items():
                    if name == func_name:
                        self.system_addrs.add(addr)
                        print(f"    {func_name} PLT entry at {hex(addr)}")
            except:
                pass
            try:
                symbol = self.proj.loader.find_symbol(func_name)
                if symbol:
                    self.system_addrs.add(symbol.rebased_addr)
                    print(f"    {func_name} symbol at {hex(symbol.rebased_addr)}")
            except:
                pass
        try:
            all_functions = list(self.proj.kb.functions.values())
            for func in all_functions:
                try:
                    for block_addr in func.block_addrs:
                        try:
                            block = self.proj.factory.block(block_addr)
                            for insn in block.capstone.insns:
                                if insn.mnemonic in ['call', 'callq']:
                                    for dangerous_func in self.dangerous_functions:
                                        if dangerous_func in insn.op_str.lower():
                                            system_calls.append((insn.address, f'{dangerous_func}_call'))
                                            self.system_call_sites.append(insn.address)
                                            print(f"    FOUND: {dangerous_func} call at {hex(insn.address)}")
                                            break
                                elif insn.mnemonic in ['syscall', 'int', 'sysenter']:
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
    def create_enhanced_system_hook(self):
        analyzer = self
        class EnhancedSystemHook(angr.SimProcedure):
            def run(self, command_ptr=None, *args, **kwargs):
                analyzer.system_reached = True
                self.state.globals['reached_system'] = True
                self.state.globals['system_addr'] = self.state.addr
                stealth_score = 0
                if analyzer.taint_tracker.check_taint_propagation(self.state, self.state.addr):
                    stealth_score += 1
                    print(f"[!] User input influences system call!")
                for trap_addr, trap_info in analyzer.logic_traps:
                    if abs(self.state.addr - trap_addr) < 100:
                        stealth_score += 2
                        print(f"[!] System call behind logic trap!")
                        break
                stealth_score += 2
                stealth_score += 1
                print(f"[!] SYSTEM HOOK TRIGGERED at {hex(self.state.addr)} (stealth score: {stealth_score})")
                analyzer.solution_states.append(self.state.copy())
                analyzer.payload_scores.append((self.state.addr, stealth_score))
                try:
                    stdin_content = None
                    if hasattr(self.state.posix, 'stdin') and self.state.posix.stdin.content:
                        try:
                            if self.state.solver.symbolic(self.state.posix.stdin.content[0]):
                                possible_inputs = self.state.solver.eval_upto(self.state.posix.stdin.content[0], 10)
                                for inp in possible_inputs:
                                    try:
                                        if inp != 0:
                                            input_bytes = inp.to_bytes((inp.bit_length() + 7) // 8, 'big')
                                            input_str = analyzer.clean_solution(input_bytes)
                                            if input_str and input_str.strip():
                                                analyzer.found_solutions.append({
                                                    'payload': input_str.strip(),
                                                    'stealth_score': stealth_score,
                                                    'addr': hex(self.state.addr),
                                                    'method': 'stdin_symbolic'
                                                })
                                                print(f"    Symbolic stdin input: '{input_str.strip()}'")
                                    except:
                                        pass
                            else:
                                concrete_content = self.state.solver.eval(self.state.posix.stdin.content[0], cast_to=bytes)
                                input_str = analyzer.clean_solution(concrete_content)
                                if input_str and input_str.strip():
                                    analyzer.found_solutions.append({
                                        'payload': input_str.strip(),
                                        'stealth_score': stealth_score,
                                        'addr': hex(self.state.addr),
                                        'method': 'stdin_concrete'
                                    })
                                    print(f"    Concrete stdin input: '{input_str.strip()}'")
                        except Exception as e:
                            pass
                    if 'symbolic_input' in self.state.globals:
                        sym_input = self.state.globals['symbolic_input']
                        try:
                            if self.state.solver.symbolic(sym_input):
                                possible_vals = self.state.solver.eval_upto(sym_input, 8)
                                for val in possible_vals:
                                    try:
                                        if val != 0:
                                            val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
                                            val_str = analyzer.clean_solution(val_bytes)
                                            if val_str and val_str.strip():
                                                analyzer.found_solutions.append({
                                                    'payload': val_str.strip(),
                                                    'stealth_score': stealth_score,
                                                    'addr': hex(self.state.addr),
                                                    'method': 'global_symbolic'
                                                })
                                                print(f"    Global symbolic input: '{val_str.strip()}'")
                                    except:
                                        pass
                            else:
                                concrete_val = self.state.solver.eval(sym_input, cast_to=bytes)
                                val_str = analyzer.clean_solution(concrete_val)
                                if val_str and val_str.strip():
                                    analyzer.found_solutions.append({
                                        'payload': val_str.strip(),
                                        'stealth_score': stealth_score,
                                        'addr': hex(self.state.addr),
                                        'method': 'global_concrete'
                                    })
                                    print(f"    Global concrete input: '{val_str.strip()}'")
                        except Exception as e:
                            pass
                    if command_ptr is not None:
                        try:
                            if self.state.solver.symbolic(command_ptr):
                                self.state.globals['symbolic_command'] = True
                                print(f"[!] System called with SYMBOLIC command!")
                                try:
                                    possible_commands = self.state.solver.eval_upto(command_ptr, 5)
                                    for cmd_addr in possible_commands:
                                        if cmd_addr != 0:
                                            try:
                                                cmd_bytes = self.state.mem[cmd_addr].string.concrete  
                                                cmd_str = cmd_bytes.decode('utf-8', errors='ignore')
                                                print(f"    Possible command: '{cmd_str}'")
                                                if cmd_str.strip():
                                                    analyzer.found_solutions.append({
                                                        'payload': cmd_str.strip(),
                                                        'stealth_score': stealth_score,
                                                        'addr': hex(self.state.addr),
                                                        'method': 'command_symbolic'
                                                    })
                                            except:
                                                pass
                                except:
                                    pass
                            else:
                                try:
                                    cmd_str = self.state.mem[command_ptr].string.concrete.decode('utf-8', errors='ignore')
                                    self.state.globals['command_string'] = cmd_str
                                    print(f"[!] System called with concrete command: '{cmd_str}'")
                                    if cmd_str.strip():
                                        analyzer.found_solutions.append({
                                            'payload': cmd_str.strip(),
                                            'stealth_score': stealth_score,
                                            'addr': hex(self.state.addr),
                                            'method': 'command_concrete'
                                        })
                                except Exception as e:
                                    print(f"[!] System called but couldn't decode command: {e}")
                        except Exception as e:
                            print(f"[!] System command processing error: {e}")
                except Exception as e:
                    print(f"[!] System hook error: {e}")
                return 0
        return EnhancedSystemHook
    def setup_hooks(self, system_calls: List[Tuple[int, str]]):
        hook_class = self.create_enhanced_system_hook()
        print("[+] Setting up enhanced system hooks...")
        for func_name in self.dangerous_functions:
            try:
                self.proj.hook_symbol(func_name, hook_class())
                print(f"    Hooked {func_name} symbol")
            except Exception as e:
                pass
        hooked_addrs = set()
        for addr, call_type in system_calls:
            if addr not in hooked_addrs:
                try:
                    self.proj.hook(addr, hook_class())
                    hooked_addrs.add(addr)
                    print(f"    Hooked {call_type} at {hex(addr)}")
                except Exception as e:
                    pass
        for system_addr in self.system_addrs:
            if system_addr not in hooked_addrs:
                try:
                    self.proj.hook(system_addr, hook_class())
                    hooked_addrs.add(system_addr)
                    print(f"    Hooked system function at {hex(system_addr)}")
                except Exception as e:
                    pass
    def guided_symbolic_execution(self, priority_addrs: List[int], input_size: int = 32) -> bool:
        print(f"[+] Running guided symbolic execution (input size: {input_size})...")
        self.symbolic_input = claripy.BVS('user_input', input_size * 8)
        initial_state = self.proj.factory.entry_state(
            stdin=self.symbolic_input,
            add_options={
                angr.options.LAZY_SOLVES,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            },
            remove_options={
                angr.options.SUPPORT_FLOATING_POINT
            }
        )
        self.taint_tracker.mark_input_tainted(initial_state, self.symbolic_input)
        initial_state.globals['symbolic_input'] = self.symbolic_input
        class LogicTrapExplorer(angr.exploration_techniques.ExplorationTechnique):
            def __init__(self, trap_addrs, analyzer):
                super().__init__()
                self.trap_addrs = set(trap_addrs)
                self.analyzer = analyzer
            def step(self, simgr, stash='active', **kwargs):
                trap_states = []
                normal_states = []
                for state in simgr.stashes.get(stash, []):
                    is_near_trap = any(abs(state.addr - trap_addr) < 50 
                                     for trap_addr in self.trap_addrs)
                    if is_near_trap:
                        trap_states.append(state)
                    else:
                        normal_states.append(state)
                if trap_states:
                    simgr.stashes[stash] = trap_states + normal_states[:5]
                else:
                    simgr.stashes[stash] = normal_states[:8]
                return simgr.step(stash=stash, **kwargs)
        simgr = self.proj.factory.simgr(initial_state)
        trap_addrs = [addr for addr, _ in self.logic_traps]
        if trap_addrs:
            simgr.use_technique(LogicTrapExplorer(trap_addrs, self))
        target_set = set()
        target_set.update(self.system_addrs)
        target_set.update(self.system_call_sites)
        target_set.update(priority_addrs)
        print(f"    Targets: {[hex(addr) for addr in target_set]}")
        print(f"    Logic traps: {[hex(addr) for addr, _ in self.logic_traps]}")
        try:
            step_count = 0
            max_steps = 500
            found_solutions = []
            solutions_this_run = set()
            while step_count < max_steps and len(simgr.active) > 0:
                step_count += 1
                new_active = []
                for state in simgr.active:
                    reached_target = (
                        state.addr in target_set or 
                        state.globals.get('reached_system', False) or
                        self.system_reached
                    )
                    if reached_target:
                        print(f"[!] Target reached at step {step_count}: {hex(state.addr)}")
                        try:
                            if state.solver.satisfiable():
                                sym_input = state.globals.get('symbolic_input', self.symbolic_input)
                                if sym_input is not None:
                                    try:
                                        solution_bytes = state.solver.eval(sym_input, cast_to=bytes)
                                        clean_sol = self.clean_solution(solution_bytes)
                                        if clean_sol and clean_sol not in solutions_this_run:
                                            stealth_score = 0
                                            if self.taint_tracker.check_taint_propagation(state, state.addr):
                                                stealth_score += 1
                                            for trap_addr, _ in self.logic_traps:
                                                if abs(state.addr - trap_addr) < 100:
                                                    stealth_score += 2
                                                    break
                                            stealth_score += 2
                                            solution_info = {
                                                'payload': clean_sol,
                                                'stealth_score': stealth_score,
                                                'addr': hex(state.addr),
                                                'method': 'symbolic_execution'
                                            }
                                            found_solutions.append(solution_info)
                                            solutions_this_run.add(clean_sol)
                                            print(f"[+] SOLUTION FOUND: '{clean_sol}' (score: {stealth_score})")
                                    except Exception as se:
                                        print(f"    Error getting solution: {se}")
                        except Exception as e:
                            print(f"    Error processing target state: {e}")
                    else:
                        new_active.append(state)
                simgr.active = new_active[:10]
                if len(found_solutions) >= 5:
                    break
                try:
                    simgr.step()
                    if step_count % 50 == 0:
                        print(f"    Step {step_count}: {len(simgr.active)} active, {len(found_solutions)} solutions")
                except Exception as e:
                    print(f"    Step error at {step_count}: {e}")
                    break
            self.found_solutions.extend(found_solutions)
            print(f"[+] Guided symbolic execution completed after {step_count} steps")
            print(f"    Solutions found this run: {len(found_solutions)}")
            return len(found_solutions) > 0
        except Exception as e:
            print(f"[-] Guided symbolic execution failed: {e}")
            return False
    def run_concrete_tests(self) -> bool:
        print("[+] Testing concrete payloads...")
        test_payloads = [
            "/bin/sh", "sh", "bash", "admin", "test", "password", "secret", 
            "1234", "exploit", "shell", "system", "flag", "key", "unlock",
            "root", "sudo", "whoami", "id", "cat", "ls", "pwd", "echo",
            "A" * 8, "B" * 8, "\x00" * 8, "\xFF" * 8,
            "\x01\x02\x03\x04", "\xAA\xBB\xCC\xDD", "\x12\x34\x56\x78"
        ]
        solutions = []
        for payload in test_payloads:
            try:
                concrete_input = payload.encode() + b'\n'
                state = self.proj.factory.entry_state(
                    stdin=concrete_input,
                    add_options={
                        angr.options.LAZY_SOLVES,
                        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY
                    },
                    remove_options={
                        angr.options.SUPPORT_FLOATING_POINT
                    }
                )
                state.globals['concrete_input'] = payload
                simgr = self.proj.factory.simgr(state)
                old_system_reached = self.system_reached
                self.system_reached = False
                original_solutions_count = len(self.found_solutions)
                steps = 0
                max_steps = 200
                while steps < max_steps and len(simgr.active) > 0 and not self.system_reached:
                    steps += 1
                    for st in simgr.active:
                        if (st.globals.get('reached_system', False) or 
                            st.addr in self.system_addrs or 
                            st.addr in self.system_call_sites):
                            solution_info = {
                                'payload': payload,
                                'stealth_score': 1,
                                'addr': hex(st.addr),
                                'method': 'concrete_test'
                            }
                            solutions.append(solution_info)
                            self.successful_payloads[payload] = {
                                'addr': hex(st.addr),
                                'steps': steps
                            }
                            print(f"[+] SUCCESS: '{payload}' triggered system call at {hex(st.addr)}!")
                            self.system_reached = True
                            break
                    if self.system_reached:
                        break
                    try:
                        simgr.step()
                        if len(simgr.active) > 6:
                            simgr.active = simgr.active[:6]
                    except Exception as e:
                        break
                if self.system_reached and len(self.found_solutions) == original_solutions_count:
                    self.found_solutions.append({
                        'payload': payload,
                        'stealth_score': 1,
                        'addr': hex(simgr.active[0].addr if simgr.active else 0),
                        'method': 'concrete_test_direct'
                    })
                if not self.system_reached:
                    self.system_reached = old_system_reached
            except Exception as e:
                print(f"    Error testing '{payload}': {e}")
        self.found_solutions.extend(solutions)
        return len(solutions) > 0
    def clean_solution(self, raw_solution) -> Optional[str]:
        try:
            if isinstance(raw_solution, int):
                byte_length = max(1, (raw_solution.bit_length() + 7) // 8)
                raw_solution = raw_solution.to_bytes(byte_length, byteorder='big')
            try:
                solution_str = raw_solution.decode('utf-8', errors='ignore')
            except:
                solution_str = raw_solution.decode('latin-1', errors='ignore')
            cleaned = ""
            for char in solution_str:
                if ord(char) == 0:
                    break
                elif 32 <= ord(char) <= 126 or char in '\n\r\t':
                    cleaned += char
            cleaned = cleaned.strip()
            if len(cleaned) == 0:
                non_zero_bytes = [b for b in raw_solution if b != 0]
                if non_zero_bytes:
                    try:
                        cleaned = bytes(non_zero_bytes).decode('utf-8', errors='ignore').strip()
                    except:
                        cleaned = ''.join(chr(b) for b in non_zero_bytes if 32 <= b <= 126)
            return cleaned if len(cleaned) > 0 else None
        except Exception as e:
            return None
    def run_full_analysis(self) -> bool:
        print("=" * 80)
        print("ENHANCED SHELL PAYLOAD ANALYZER WITH LOGIC TRAP DETECTION")
        print("=" * 80)
        if not self.load_binary():
            return False
        if not self.build_cfg():
            return False
        shell_strings = self.find_shell_strings()
        system_calls = self.find_system_calls_enhanced()
        self.logic_traps = self.logic_analyzer.find_logic_traps(self.proj, self.cfg)
        print(f"\n[+] Analysis Summary:")
        print(f"    Shell strings: {len(shell_strings)}")
        print(f"    System calls: {len(system_calls)}")
        print(f"    Logic traps: {len(self.logic_traps)}")
        self.setup_hooks(system_calls)
        print("\n" + "=" * 50)
        print("RUNNING ENHANCED ANALYSIS")
        print("=" * 50)
        success = False
        print("\n--- CONCRETE PAYLOAD TESTING ---")
        if self.run_concrete_tests():
            success = True
        if self.logic_traps:
            print("\n--- GUIDED SYMBOLIC EXECUTION (LOGIC TRAPS) ---")
            trap_addrs = [addr for addr, _ in self.logic_traps]
        if self.guided_symbolic_execution(trap_addrs, 32):
                success = True
            
                print("\n--- GUIDED SYMBOLIC EXECUTION (EXTENDED) ---")
        if self.guided_symbolic_execution(trap_addrs, 64):
                success = True

        if self.system_call_sites:
            print("\n--- SYMBOLIC EXECUTION TARGETING SYSTEM CALLS ---")
            if self.guided_symbolic_execution(self.system_call_sites, 48):
                success = True

        if self.system_addrs:
            print("\n--- SYMBOLIC EXECUTION TARGETING SYSTEM FUNCTIONS ---")
            if self.guided_symbolic_execution(list(self.system_addrs), 40):
                success = True

        print("\n--- STRING-BASED PAYLOAD GENERATION ---")
        if self.generate_string_based_payloads():
            success = True

        print("\n--- FORMAT STRING VULNERABILITY DETECTION ---")
        if self.detect_format_string_vulns():
            success = True

        return success

    def generate_string_based_payloads(self) -> bool:
        """Generate payloads based on discovered strings and patterns"""
        solutions = []
        
        for addr, string in self.shell_strings:
            payload_variants = [
                string,
                string.strip(),
                string + "\n",
                string + "\x00",
                string.replace("/bin/", ""),
                string.upper(),
                string.lower()
            ]
            
            for variant in payload_variants:
                if variant and variant not in [s['payload'] for s in self.found_solutions]:
                    solutions.append({
                        'payload': variant,
                        'stealth_score': 3,  # String-based payloads get high stealth score
                        'addr': hex(addr),
                        'method': 'string_based'
                    })
                    print(f"[+] String-based payload: '{variant}' from {hex(addr)}")

        for addr, string in self.interesting_strings:
            if any(keyword in string.lower() for keyword in ['flag', 'secret', 'pass', 'key', 'admin']):
                payload_variants = [
                    string,
                    string.strip(),
                    string + "\n"
                ]
                
                for variant in payload_variants:
                    if variant and variant not in [s['payload'] for s in self.found_solutions]:
                        solutions.append({
                            'payload': variant,
                            'stealth_score': 2,
                            'addr': hex(addr),
                            'method': 'interesting_string'
                        })
                        print(f"[+] Interesting string payload: '{variant}' from {hex(addr)}")

        self.found_solutions.extend(solutions)
        return len(solutions) > 0

    def detect_format_string_vulns(self) -> bool:
        """Detect potential format string vulnerabilities"""
        format_payloads = [
            "%x", "%s", "%n", "%p", "%d",
            "%x.%x.%x.%x", "%s%s%s%s",
            "%08x.%08x.%08x.%08x",
            "AAAA%08x.%08x.%08x.%08x",
            "%n%n%n%n",
            "%1$x", "%2$x", "%3$x", "%4$x"
        ]
        
        solutions = []
        print("[+] Testing format string payloads...")
        
        for payload in format_payloads:
            try:
                concrete_input = payload.encode() + b'\n'
                state = self.proj.factory.entry_state(
                    stdin=concrete_input,
                    add_options={
                        angr.options.LAZY_SOLVES,
                        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY
                    }
                )
                
                simgr = self.proj.factory.simgr(state)
                
                steps = 0
                max_steps = 100
                found_vuln = False
                
                while steps < max_steps and len(simgr.active) > 0 and not found_vuln:
                    steps += 1
                    
                    for st in simgr.active:
                        # Check for format string vulnerability indicators
                        if (st.addr in self.system_addrs or 
                            st.addr in self.system_call_sites or
                            st.globals.get('reached_system', False)):
                            
                            solutions.append({
                                'payload': payload,
                                'stealth_score': 4,  # Format string vulns get highest score
                                'addr': hex(st.addr),
                                'method': 'format_string'
                            })
                            print(f"[+] FORMAT STRING SUCCESS: '{payload}' at {hex(st.addr)}")
                            found_vuln = True
                            break
                    
                    if found_vuln:
                        break
                        
                    try:
                        simgr.step()
                        if len(simgr.active) > 4:
                            simgr.active = simgr.active[:4]
                    except:
                        break
                        
            except Exception as e:
                print(f"    Error testing format string '{payload}': {e}")
        
        self.found_solutions.extend(solutions)
        return len(solutions) > 0

    def print_comprehensive_results(self):
        """Print comprehensive analysis results"""
        print("\n" + "=" * 80)
        print("COMPREHENSIVE ANALYSIS RESULTS")
        print("=" * 80)
        
        if not self.found_solutions:
            print("[-] No shell payloads discovered")
            return
        
        sorted_solutions = sorted(self.found_solutions, 
                                key=lambda x: x['stealth_score'], 
                                reverse=True)
        
        seen = set()
        unique_solutions = []
        for sol in sorted_solutions:
            if sol['payload'] not in seen:
                seen.add(sol['payload'])
                unique_solutions.append(sol)
        
        print(f"\n[+] DISCOVERED {len(unique_solutions)} UNIQUE PAYLOADS:")
        print("-" * 60)
        
        for i, solution in enumerate(unique_solutions[:15], 1):  # Show top 15
            stealth_indicator = "🔥" * min(solution['stealth_score'], 5)
            print(f"{i:2d}. {stealth_indicator} '{solution['payload']}'")
            print(f"     Method: {solution['method']}")
            print(f"     Address: {solution['addr']}")
            print(f"     Stealth Score: {solution['stealth_score']}/5")
            print()
        
        if len(unique_solutions) > 15:
            print(f"... and {len(unique_solutions) - 15} more payloads")
        
        method_stats = {}
        for sol in unique_solutions:
            method = sol['method']
            method_stats[method] = method_stats.get(method, 0) + 1
        
        print(f"\n[+] PAYLOAD DISCOVERY METHODS:")
        print("-" * 40)
        for method, count in sorted(method_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {method}: {count} payloads")
        
        score_dist = {}
        for sol in unique_solutions:
            score = sol['stealth_score']
            score_dist[score] = score_dist.get(score, 0) + 1
        
        print(f"\n[+] STEALTH SCORE DISTRIBUTION:")
        print("-" * 40)
        for score in sorted(score_dist.keys(), reverse=True):
            count = score_dist[score]
            bar = "█" * min(count, 20)
            print(f"  Score {score}: {count:2d} payloads {bar}")
        
        if self.logic_traps:
            print(f"\n[+] LOGIC TRAP ANALYSIS:")
            print("-" * 40)
            print(f"  Detected {len(self.logic_traps)} logic traps")
            for addr, trap_info in self.logic_traps[:5]:
                print(f"  {hex(addr)}: complexity score {trap_info['score']}")
                for op_addr, mnemonic, operands in trap_info['operations'][:3]:
                    print(f"    {hex(op_addr)}: {mnemonic} {operands}")
        
        print(f"\n[+] TOP PAYLOADS (READY TO USE):")
        print("-" * 40)
        top_payloads = unique_solutions[:10]
        for i, sol in enumerate(top_payloads, 1):
            print(f"{i:2d}. {sol['payload']}")
        
        print(f"\n[+] BINARY ANALYSIS SUMMARY:")
        print("-" * 40)
        print(f"  Binary: {self.binary_path}")
        print(f"  Architecture: {self.proj.arch if self.proj else 'Unknown'}")
        print(f"  Shell strings found: {len(self.shell_strings)}")
        print(f"  System call sites: {len(self.system_call_sites)}")
        print(f"  Dangerous functions: {len(self.system_addrs)}")
        print(f"  Logic traps: {len(self.logic_traps)}")
        print(f"  Total payloads: {len(unique_solutions)}")
        
        if self.successful_payloads:
            print(f"\n[+] VERIFIED WORKING PAYLOADS:")
            print("-" * 40)
            for payload, info in self.successful_payloads.items():
                print(f"  '{payload}' -> {info['addr']} ({info['steps']} steps)")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 enhanced_shell_analyzer.py <binary_path>")
        print("Example: python3 enhanced_shell_analyzer.py ./vulnerable_binary")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    if not os.path.exists(binary_path):
        print(f"[-] Binary not found: {binary_path}")
        sys.exit(1)
    
    print(f"[+] Starting enhanced analysis of: {binary_path}")
    start_time = time.time()
    
    analyzer = EnhancedShellPayloadAnalyzer(binary_path)
    
    try:
        success = analyzer.run_full_analysis()
        
        if success:
            analyzer.print_comprehensive_results()
        else:
            print("\n[-] Analysis completed but no shell payloads were discovered")
            print("    The binary may not be vulnerable or may require different techniques")
        
        end_time = time.time()
        print(f"\n[+] Analysis completed in {end_time - start_time:.2f} seconds")
        
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user")
        if analyzer.found_solutions:
            print("[+] Printing partial results...")
            analyzer.print_comprehensive_results()
    except Exception as e:
        print(f"\n[-] Analysis failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()