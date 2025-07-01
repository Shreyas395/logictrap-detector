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
class ExternalGateCatalog:
    def __init__(self):
        self.randomness_gates = {'rand', 'random', 'srand', 'srandom', 'getrandom', 'arc4random', 'urandom'}
        self.env_gates = {'getenv', 'setenv', 'unsetenv', 'environ', 'putenv', 'clearenv'}
        self.file_gates = {'access', 'stat', 'lstat', 'fstat', 'open', 'openat', 'close', 'read', 'write', 'fopen', 'fclose', 'fread', 'fwrite'}
        self.time_gates = {'time', 'gettimeofday', 'clock_gettime', 'localtime', 'gmtime', 'strftime'}
        self.uid_gates = {'getuid', 'geteuid', 'getgid', 'getegid', 'setuid', 'seteuid', 'setgid', 'setegid'}
        self.network_gates = {'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv', 'gethostname'}
        self.proc_gates = {'getpid', 'getppid', 'fork', 'vfork', 'clone', 'wait', 'waitpid', 'kill'}
        self.all_gates = set()
        self.all_gates.update(self.randomness_gates)
        self.all_gates.update(self.env_gates)
        self.all_gates.update(self.file_gates)
        self.all_gates.update(self.time_gates)
        self.all_gates.update(self.uid_gates)
        self.all_gates.update(self.network_gates)
        self.all_gates.update(self.proc_gates)
        self.discovered_gates = {}
        self.symbolic_models = {}
    def catalog_binary_gates(self, proj):
        print("[+] Cataloging external gates...")
        for gate in self.all_gates:
            try:
                if gate in proj.kb.functions:
                    func = proj.kb.functions[gate]
                    self.discovered_gates[gate] = func.addr
                    print(f"    {gate} function at {hex(func.addr)}")
            except:
                pass
            try:
                for addr, name in proj.loader.main_object.plt.items():
                    if name == gate:
                        self.discovered_gates[gate] = addr
                        print(f"    {gate} PLT at {hex(addr)}")
            except:
                pass
            try:
                symbol = proj.loader.find_symbol(gate)
                if symbol:
                    self.discovered_gates[gate] = symbol.rebased_addr
                    print(f"    {gate} symbol at {hex(symbol.rebased_addr)}")
            except:
                pass
        return self.discovered_gates
    def create_symbolic_models(self):
        self.symbolic_models = {}
        for gate_name in self.discovered_gates:
            if gate_name in self.randomness_gates:
                self.symbolic_models[gate_name] = self.create_randomness_model(gate_name)
            elif gate_name in self.env_gates:
                self.symbolic_models[gate_name] = self.create_env_model(gate_name)
            elif gate_name in self.file_gates:
                self.symbolic_models[gate_name] = self.create_file_model(gate_name)
            elif gate_name in self.time_gates:
                self.symbolic_models[gate_name] = self.create_time_model(gate_name)
            elif gate_name in self.uid_gates:
                self.symbolic_models[gate_name] = self.create_uid_model(gate_name)
            elif gate_name in self.network_gates:
                self.symbolic_models[gate_name] = self.create_network_model(gate_name)
            elif gate_name in self.proc_gates:
                self.symbolic_models[gate_name] = self.create_proc_model(gate_name)
    def create_randomness_model(self, gate_name):
        class RandomnessModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name in ['rand', 'random']:
                    sym_val = claripy.BVS(f'{gate_name}_output', 32)
                    self.state.globals[f'{gate_name}_sym'] = sym_val
                    return sym_val
                elif gate_name == 'getrandom':
                    buf_ptr = args[0] if args else claripy.BVS('getrandom_buf', 64)
                    size = args[1] if len(args) > 1 else 4
                    random_bytes = claripy.BVS('getrandom_bytes', size * 8)
                    self.state.memory.store(buf_ptr, random_bytes)
                    self.state.globals['getrandom_bytes'] = random_bytes
                    return size
                elif gate_name in ['arc4random']:
                    sym_val = claripy.BVS(f'{gate_name}_output', 32)
                    self.state.globals[f'{gate_name}_sym'] = sym_val
                    return sym_val
                return claripy.BVS(f'{gate_name}_default', 32)
        return RandomnessModel
    def create_env_model(self, gate_name):
        class EnvModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name == 'getenv':
                    var_name_ptr = args[0] if args else None
                    if var_name_ptr:
                        try:
                            var_name = self.state.mem[var_name_ptr].string.concrete.decode('utf-8')
                            env_value = claripy.BVS(f'env_{var_name}', 64 * 8)
                            env_ptr = self.state.heap.allocate(64)
                            self.state.memory.store(env_ptr, env_value)
                            self.state.globals[f'env_{var_name}'] = env_value
                            return env_ptr
                        except:
                            env_value = claripy.BVS('env_unknown', 64 * 8)
                            env_ptr = self.state.heap.allocate(64)
                            self.state.memory.store(env_ptr, env_value)
                            self.state.globals['env_unknown'] = env_value
                            return env_ptr
                return claripy.BVS(f'{gate_name}_result', 64)
        return EnvModel
    def create_file_model(self, gate_name):
        class FileModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name == 'access':
                    path_ptr = args[0] if args else None
                    mode = args[1] if len(args) > 1 else 0
                    access_result = claripy.BVS(f'access_result_{hex(self.state.addr)}', 32)
                    self.state.globals[f'access_{hex(self.state.addr)}'] = access_result
                    return access_result
                elif gate_name in ['open', 'openat']:
                    fd_result = claripy.BVS(f'{gate_name}_fd', 32)
                    self.state.globals[f'{gate_name}_fd'] = fd_result
                    return fd_result
                elif gate_name in ['stat', 'lstat', 'fstat']:
                    stat_result = claripy.BVS(f'{gate_name}_result', 32)
                    self.state.globals[f'{gate_name}_result'] = stat_result
                    return stat_result
                elif gate_name in ['read', 'fread']:
                    bytes_read = claripy.BVS(f'{gate_name}_bytes', 32)
                    self.state.globals[f'{gate_name}_bytes'] = bytes_read
                    return bytes_read
                return claripy.BVS(f'{gate_name}_default', 32)
        return FileModel
    def create_time_model(self, gate_name):
        class TimeModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name == 'time':
                    time_val = claripy.BVS('time_value', 64)
                    self.state.globals['time_value'] = time_val
                    return time_val
                elif gate_name == 'gettimeofday':
                    tv_ptr = args[0] if args else None
                    if tv_ptr:
                        sec_val = claripy.BVS('tv_sec', 64)
                        usec_val = claripy.BVS('tv_usec', 64)
                        self.state.memory.store(tv_ptr, sec_val)
                        self.state.memory.store(tv_ptr + 8, usec_val)
                        self.state.globals['tv_sec'] = sec_val
                        self.state.globals['tv_usec'] = usec_val
                    return 0
                return claripy.BVS(f'{gate_name}_time', 64)
        return TimeModel
    def create_uid_model(self, gate_name):
        class UidModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                uid_val = claripy.BVS(f'{gate_name}_uid', 32)
                self.state.globals[f'{gate_name}_uid'] = uid_val
                return uid_val
        return UidModel
    def create_network_model(self, gate_name):
        class NetworkModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name == 'socket':
                    sock_fd = claripy.BVS('socket_fd', 32)
                    self.state.globals['socket_fd'] = sock_fd
                    return sock_fd
                elif gate_name in ['bind', 'listen', 'connect']:
                    result = claripy.BVS(f'{gate_name}_result', 32)
                    self.state.globals[f'{gate_name}_result'] = result
                    return result
                return claripy.BVS(f'{gate_name}_net', 32)
        return NetworkModel
    def create_proc_model(self, gate_name):
        class ProcModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name in ['getpid', 'getppid']:
                    pid_val = claripy.BVS(f'{gate_name}_pid', 32)
                    self.state.globals[f'{gate_name}_pid'] = pid_val
                    return pid_val
                elif gate_name in ['fork', 'vfork']:
                    fork_result = claripy.BVS(f'{gate_name}_result', 32)
                    self.state.globals[f'{gate_name}_result'] = fork_result
                    return fork_result
                return claripy.BVS(f'{gate_name}_proc', 32)
        return ProcModel
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
                    except:
                        pass
            return {
                'score': complexity_score,
                'operations': operations,
                'comparisons': comparisons,
                'gate_calls': gate_calls,
                'is_trap': complexity_score >= 3
            }
        except Exception as e:
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
class EnhancedShellPayloadAnalyzer:
    def __init__(self, binary_path: str, max_input_size: int = 256):
        self.binary_path = binary_path
        self.max_input_size = max_input_size
        self.proj = None
        self.cfg = None
        self.gate_catalog = ExternalGateCatalog()
        self.dangerous_functions = {'system', 'execve', 'execvp', 'execl', 'execlp', 'execle', 'execv', 'posix_spawn', 'posix_spawnp', 'popen', 'sh', 'bash', 'zsh', 'fork', 'vfork', 'clone', 'waitpid', 'wait', 'wait3', 'wait4'}
        self.shell_syscalls = {11: 'execve', 59: 'execve', 57: 'fork', 58: 'vfork', 56: 'clone'}
        self.input_functions = {'fgets', 'gets', 'scanf', 'fscanf', 'read', 'fread', 'getline', 'getdelim', 'fgetc', 'getchar', 'getc', '__isoc99_scanf'}
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
        self.symbolic_constraints = []
        self.gate_solutions = {}
    def load_binary(self) -> bool:
        try:
            self.proj = angr.Project(self.binary_path, auto_load_libs=False, load_options={'main_opts': {'base_addr': 0}, 'auto_load_libs': False})
            print(f"[+] Loaded binary: {self.binary_path}")
            print(f"[+] Architecture: {self.proj.arch}")
            print(f"[+] Entry point: {hex(self.proj.entry)}")
            discovered_gates = self.gate_catalog.catalog_binary_gates(self.proj)
            self.gate_catalog.create_symbolic_models()
            self.setup_gate_hooks()
            return True
        except Exception as e:
            print(f"[-] Failed to load binary: {e}")
            return False
    def setup_gate_hooks(self):
        print("[+] Setting up symbolic gate hooks...")
        for gate_name, gate_addr in self.gate_catalog.discovered_gates.items():
            if gate_name in self.gate_catalog.symbolic_models:
                try:
                    self.proj.hook_symbol(gate_name, self.gate_catalog.symbolic_models[gate_name]())
                    print(f"    Hooked {gate_name} symbol")
                except:
                    pass
                try:
                    self.proj.hook(gate_addr, self.gate_catalog.symbolic_models[gate_name]())
                    print(f"    Hooked {gate_name} at {hex(gate_addr)}")
                except:
                    pass
    def build_cfg(self) -> bool:
        print("[+] Building CFG with symbolic gates...")
        try:
            self.cfg = self.proj.analyses.CFGFast(normalize=True, data_references=True, resolve_indirect_jumps=True, force_complete_scan=False)
            print(f"[+] CFGFast built with {len(self.cfg.graph.nodes)} nodes")
            return True
        except Exception as e:
            print(f"[-] CFGFast failed: {e}")
            return False
    def find_shell_strings(self) -> List[Tuple[int, str]]:
        print("[+] Finding shell-related strings...")
        shell_patterns = [r'/bin/sh', r'/bin/bash', r'/bin/zsh', r'sh\s*$', r'bash\s*$', r'system\s*\(', r'exec[lv]', r'cmd\.exe', r'powershell', r'shell', r'whoami', r'id\s*$', r'cat\s+', r'ls\s+', r'/usr/bin/', r'/sbin/', r'nc\s+', r'netcat', r'flag', r'secret', r'password', r'admin', r'root']
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
                gate_solutions = {}
                for gate_name in analyzer.gate_catalog.discovered_gates:
                    gate_key = f'{gate_name}_sym'
                    if gate_key in self.state.globals:
                        sym_val = self.state.globals[gate_key]
                        if analyzer.symbolic_input and self.state.solver.symbolic(sym_val):
                            try:
                                concrete_val = self.state.solver.eval(sym_val)
                                gate_solutions[gate_name] = concrete_val
                                print(f"    Gate {gate_name}: {concrete_val}")
                                stealth_score += 1
                            except:
                                pass
                    for env_key in [k for k in self.state.globals.keys() if k.startswith('env_')]:
                        try:
                            env_val = self.state.globals[env_key]
                            if self.state.solver.symbolic(env_val):
                                concrete_env = self.state.solver.eval(env_val, cast_to=bytes)
                                gate_solutions[env_key] = concrete_env
                                print(f"    {env_key}: {concrete_env}")
                                stealth_score += 1
                        except:
                            pass
                for trap_addr, trap_info in analyzer.logic_traps:
                    if abs(self.state.addr - trap_addr) < 100:
                        stealth_score += 3
                        print(f"[!] System call behind enhanced logic trap!")
                        break
                stealth_score += 2
                print(f"[!] ENHANCED SYSTEM HOOK at {hex(self.state.addr)} (score: {stealth_score})")
                analyzer.solution_states.append(self.state.copy())
                analyzer.payload_scores.append((self.state.addr, stealth_score))
                analyzer.gate_solutions[self.state.addr] = gate_solutions
                try:
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
                                                    'method': 'enhanced_symbolic',
                                                    'gates': gate_solutions
                                                })
                                                print(f"    Enhanced symbolic input: '{val_str.strip()}'")
                                    except:
                                        pass
                        except Exception as e:
                            pass
                except Exception as e:
                    print(f"[!] Enhanced system hook error: {e}")
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
    def add_primary_input_constraints(self, state):
        print("[+] Adding primary input constraints...")
        if 'symbolic_input' in state.globals:
            sym_input = state.globals['symbolic_input']
            input_size = sym_input.size() // 8
            for i in range(min(input_size, 32)):
                byte_val = sym_input.get_byte(i)
                state.solver.add(claripy.And(byte_val >= 32, byte_val <= 126))
                self.symbolic_constraints.append(f"byte[{i}] printable")
            if input_size >= 2:
                byte0 = sym_input.get_byte(0)
                byte1 = sym_input.get_byte(1)
                state.solver.add(claripy.And(byte0 >= 48, byte0 <= 57))
                state.solver.add(claripy.And(byte1 >= 48, byte1 <= 57))
                self.symbolic_constraints.append("first two bytes are digits")
    def guided_symbolic_execution(self, priority_addrs: List[int], input_size: int = 32) -> bool:
        print(f"[+] Running enhanced guided symbolic execution (input size: {input_size})...")
        self.symbolic_input = claripy.BVS('user_input', input_size * 8)
        initial_state = self.proj.factory.entry_state(stdin=self.symbolic_input, add_options={angr.options.LAZY_SOLVES, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}, remove_options={angr.options.SUPPORT_FLOATING_POINT})
        initial_state.globals['symbolic_input'] = self.symbolic_input
        self.add_primary_input_constraints(initial_state)
        class EnhancedLogicTrapExplorer(angr.exploration_techniques.ExplorationTechnique):
            def __init__(self, trap_addrs, gate_addrs, analyzer):
                super().__init__()
                self.trap_addrs = set(trap_addrs)
                self.gate_addrs = set(gate_addrs)
                self.analyzer = analyzer
            def step(self, simgr, stash='active', **kwargs):
                enhanced_states = []
                normal_states = []
                for state in simgr.stashes.get(stash, []):
                    is_near_trap = any(abs(state.addr - trap_addr) < 50 for trap_addr in self.trap_addrs)
                    is_near_gate = any(abs(state.addr - gate_addr) < 50 for gate_addr in self.gate_addrs)
                    if is_near_trap or is_near_gate:
                        enhanced_states.append(state)
                    else:
                        normal_states.append(state)
                if enhanced_states:
                    simgr.stashes[stash] = enhanced_states + normal_states[:3]
                else:
                    simgr.stashes[stash] = normal_states[:8]
                return simgr.step(stash=stash, **kwargs)
        simgr = self.proj.factory.simgr(initial_state)
        
        trap_addrs = [addr for addr, _ in self.logic_traps]
        gate_addrs = list(self.gate_catalog.discovered_gates.values())
        simgr.use_technique(EnhancedLogicTrapExplorer(trap_addrs, gate_addrs, self))
        
        try:
            simgr.explore(
                find=lambda s: s.globals.get('reached_system', False),
                avoid=lambda s: s.addr == 0,
                num_find=20,
                step_func=lambda sm: sm if len(sm.active) <= 12 else sm.drop(stash='active', filter_func=lambda s: len(sm.active) - 8)
            )
            
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
                                    stealth_score = 5  
                                    
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
                                            except:
                                                pass
                                    
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
                                continue
                                
                except Exception as e:
                    print(f"    Error processing found state: {e}")
                    continue
            
            return len(simgr.found) > 0
            
        except Exception as e:
            print(f"[-] Symbolic execution failed: {e}")
            return False

    def clean_solution(self, solution_bytes: bytes) -> str:
        """Clean and validate solution bytes"""
        try:
            for encoding in ['utf-8', 'ascii', 'latin-1']:
                try:
                    decoded = solution_bytes.decode(encoding)
                    cleaned = ''.join(c for c in decoded if ord(c) >= 32 and ord(c) <= 126)
                    if len(cleaned) > 0:
                        return cleaned
                except:
                    continue
            
            return solution_bytes.hex()
            
        except Exception:
            return ""

    def fuzzing_based_discovery(self, input_size: int = 64) -> List[str]:
        """Enhanced fuzzing with gate-aware payloads"""
        print(f"[+] Running enhanced fuzzing (input size: {input_size})...")
        
        base_payloads = [
            b"A" * 32,
            b"1234567890",
            b"admin",
            b"root",
            b"password",
            b"shell",
            b"/bin/sh",
            b"system",
            b"exec",
            b"0",
            b"1",
            b"-1",
            b"999999",
            b"secret",
            b"flag",
            b"debug",
            b"test"
        ]
        
        if any(gate in self.gate_catalog.discovered_gates for gate in self.gate_catalog.randomness_gates):
            base_payloads.extend([b"random", b"seed", b"entropy"])
            
        if any(gate in self.gate_catalog.discovered_gates for gate in self.gate_catalog.env_gates):
            base_payloads.extend([b"PATH", b"HOME", b"USER", b"SHELL"])
            
        if any(gate in self.gate_catalog.discovered_gates for gate in self.gate_catalog.time_gates):
            base_payloads.extend([b"1970", b"2024", b"time", b"date"])
            
        if any(gate in self.gate_catalog.discovered_gates for gate in self.gate_catalog.uid_gates):
            base_payloads.extend([b"0", b"1000", b"uid", b"gid"])
        
        fuzzing_results = []
        
        for payload in base_payloads:
            try:
                if len(payload) < input_size:
                    payload = payload + b"\x00" * (input_size - len(payload))
                else:
                    payload = payload[:input_size]
                
                concrete_input = claripy.BVV(int.from_bytes(payload, 'big'), input_size * 8)
                
                test_state = self.proj.factory.entry_state(
                    stdin=concrete_input,
                    add_options={angr.options.LAZY_SOLVES}
                )
                test_state.globals['symbolic_input'] = concrete_input
                
                simgr = self.proj.factory.simgr(test_state)
                
                try:
                    simgr.run(n=100)  
                    for stash_name, states in simgr.stashes.items():
                        for state in states:
                            if state.globals.get('reached_system', False):
                                payload_str = self.clean_solution(payload)
                                if payload_str:
                                    fuzzing_results.append(payload_str)
                                    print(f"    Fuzzing hit: '{payload_str}'")
                                break
                                
                except Exception:
                    continue
                    
            except Exception:
                continue
        
        return fuzzing_results

    def analyze_enhanced(self) -> Dict[str, Any]:
        """Main analysis function with enhanced capabilities"""
        print("="*60)
        print("ENHANCED SHELL PAYLOAD ANALYZER")
        print("="*60)
        
        if not self.load_binary():
            return {'error': 'Failed to load binary'}
        
        if not self.build_cfg():
            return {'error': 'Failed to build CFG'}
        
        shell_strings = self.find_shell_strings()
        system_calls = self.find_system_calls_enhanced()
        
        gate_addrs = set(self.gate_catalog.discovered_gates.values())
        self.logic_traps = self.logic_analyzer.find_logic_traps(self.proj, self.cfg, gate_addrs)
        
        self.setup_hooks(system_calls)
        
        found_any = False
        
        if self.guided_symbolic_execution(list(gate_addrs), 32):
            found_any = True
        
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
                except:
                    continue
        
        results = {
            'binary_path': self.binary_path,
            'discovered_gates': dict(self.gate_catalog.discovered_gates),
            'shell_strings': shell_strings,
            'system_calls': system_calls,
            'logic_traps': [(hex(addr), info) for addr, info in self.logic_traps],
            'solutions': self.found_solutions,
            'gate_solutions': self.gate_solutions,
            'analysis_success': found_any,
            'total_solutions': len(self.found_solutions),
            'highest_stealth_score': max([s.get('stealth_score', 0) for s in self.found_solutions], default=0)
        }
        
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
                print(f"    {gate_name}: {hex(gate_addr)}")
        
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
                        print(f"        {gate_name}: {gate_val}")
        
        if not results['analysis_success']:
            print("\n[-] No solutions found. Try:")
            print("    - Different input sizes")
            print("    - Manual analysis of discovered gates")
            print("    - Extended symbolic execution")


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