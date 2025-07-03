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
class ExternalGateCatalog:  # Manages sets of external “gates” (functions/syscalls) and their symbolic models
    def __init__(self):
        self.randomness_gates = {'rand', 'random', 'srand', 'srandom', 'getrandom', 'arc4random', 'urandom'}  # functions that introduce randomness
        self.env_gates = {'getenv', 'setenv', 'unsetenv', 'environ', 'putenv', 'clearenv'}  # environment variable accessors
        self.file_gates = {'access', 'stat', 'lstat', 'fstat', 'open', 'openat', 'close', 'read', 'write', 'fopen', 'fclose', 'fread', 'fwrite'}  # file I/O operations
        self.time_gates = {'time', 'gettimeofday', 'clock_gettime', 'localtime', 'gmtime', 'strftime'}  # time and date functions
        self.uid_gates = {'getuid', 'geteuid', 'getgid', 'getegid', 'setuid', 'seteuid', 'setgid', 'setegid'}  # user/group ID functions
        self.network_gates = {'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv', 'gethostname'}  # networking syscalls
        self.proc_gates = {'getpid', 'getppid', 'fork', 'vfork', 'clone', 'wait', 'waitpid', 'kill'}  # process management functions
        self.all_gates = set()  # will hold the union of all gate categories
        self.all_gates.update(self.randomness_gates)  # include randomness gates
        self.all_gates.update(self.env_gates)        # include environment gates
        self.all_gates.update(self.file_gates)       # include file I/O gates
        self.all_gates.update(self.time_gates)       # include time-related gates
        self.all_gates.update(self.uid_gates)        # include UID/GID gates
        self.all_gates.update(self.network_gates)    # include network gates
        self.all_gates.update(self.proc_gates)       # include process gates
        self.discovered_gates = {}   # to record addresses of gates found in the binary
        self.symbolic_models = {}    # to store custom SimProcedure classes for each gate

    def catalog_binary_gates(self, proj):
        print("[+] Cataloging external gates...")  # notify start of cataloging
        for gate in self.all_gates:  # iterate over every known external gate
            try:
                if gate in proj.kb.functions:  # check if the function is in the CFG
                    func = proj.kb.functions[gate]
                    self.discovered_gates[gate] = func.addr  # store its address
                    print(f"    {gate} function at {hex(func.addr)}")
            except:
                pass
            try:
                for addr, name in proj.loader.main_object.plt.items():  # scan the PLT for imports
                    if name == gate:
                        self.discovered_gates[gate] = addr  # record PLT entry address
                        print(f"    {gate} PLT at {hex(addr)}")
            except:
                pass
            try:
                symbol = proj.loader.find_symbol(gate)  # look for exported symbols
                if symbol:
                    self.discovered_gates[gate] = symbol.rebased_addr  # record symbol address
                    print(f"    {gate} symbol at {hex(symbol.rebased_addr)}")
            except:
                pass
        return self.discovered_gates  # return map of gate names to addresses

    def create_symbolic_models(self):
        self.symbolic_models = {}  # reset any existing models
        for gate_name in self.discovered_gates:  # for each found gate
            if gate_name in self.randomness_gates:
                self.symbolic_models[gate_name] = self.create_randomness_model(gate_name)  # randomness handling
            elif gate_name in self.env_gates:
                self.symbolic_models[gate_name] = self.create_env_model(gate_name)  # environment variable handling
            elif gate_name in self.file_gates:
                self.symbolic_models[gate_name] = self.create_file_model(gate_name)  # file I/O handling
            elif gate_name in self.time_gates:
                self.symbolic_models[gate_name] = self.create_time_model(gate_name)  # time handling
            elif gate_name in self.uid_gates:
                self.symbolic_models[gate_name] = self.create_uid_model(gate_name)  # UID/GID handling
            elif gate_name in self.network_gates:
                self.symbolic_models[gate_name] = self.create_network_model(gate_name)  # network handling
            elif gate_name in self.proc_gates:
                self.symbolic_models[gate_name] = self.create_proc_model(gate_name)  # process handling

    def create_randomness_model(self, gate_name):
        class RandomnessModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name in ['rand', 'random']:
                    sym_val = claripy.BVS(f'{gate_name}_output', 32)  # symbolic return for rand/random
                    self.state.globals[f'{gate_name}_sym'] = sym_val
                    return sym_val
                elif gate_name == 'getrandom':
                    buf_ptr = args[0] if args else claripy.BVS('getrandom_buf', 64)
                    size = args[1] if len(args) > 1 else 4
                    random_bytes = claripy.BVS('getrandom_bytes', size * 8)  # symbolic buffer content
                    self.state.memory.store(buf_ptr, random_bytes)
                    self.state.globals['getrandom_bytes'] = random_bytes
                    return size  # return number of bytes “read”
                elif gate_name in ['arc4random']:
                    sym_val = claripy.BVS(f'{gate_name}_output', 32)
                    self.state.globals[f'{gate_name}_sym'] = sym_val
                    return sym_val  # symbolic arc4random output
                return claripy.BVS(f'{gate_name}_default', 32)  # fallback symbolic value
        return RandomnessModel

    def create_env_model(self, gate_name):
        class EnvModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name == 'getenv':
                    var_name_ptr = args[0] if args else None
                    if var_name_ptr:
                        try:
                            var_name = self.state.mem[var_name_ptr].string.concrete.decode('utf-8')
                            env_value = claripy.BVS(f'env_{var_name}', 64 * 8)  # symbolic env var value
                            env_ptr = self.state.heap.allocate(64)
                            self.state.memory.store(env_ptr, env_value)
                            self.state.globals[f'env_{var_name}'] = env_value
                            return env_ptr  # pointer to symbolic string
                        except:
                            env_value = claripy.BVS('env_unknown', 64 * 8)
                            env_ptr = self.state.heap.allocate(64)
                            self.state.memory.store(env_ptr, env_value)
                            self.state.globals['env_unknown'] = env_value
                            return env_ptr
                return claripy.BVS(f'{gate_name}_result', 64)  # default symbolic result
        return EnvModel

    def create_file_model(self, gate_name):
        class FileModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name == 'access':
                    path_ptr = args[0] if args else None
                    mode = args[1] if len(args) > 1 else 0
                    access_result = claripy.BVS(f'access_result_{hex(self.state.addr)}', 32)
                    self.state.globals[f'access_{hex(self.state.addr)}'] = access_result
                    return access_result  # symbolic success/failure
                elif gate_name in ['open', 'openat']:
                    fd_result = claripy.BVS(f'{gate_name}_fd', 32)
                    self.state.globals[f'{gate_name}_fd'] = fd_result
                    return fd_result  # symbolic file descriptor
                elif gate_name in ['stat', 'lstat', 'fstat']:
                    stat_result = claripy.BVS(f'{gate_name}_result', 32)
                    self.state.globals[f'{gate_name}_result'] = stat_result
                    return stat_result  # symbolic stat return code
                elif gate_name in ['read', 'fread']:
                    bytes_read = claripy.BVS(f'{gate_name}_bytes', 32)
                    self.state.globals[f'{gate_name}_bytes'] = bytes_read
                    return bytes_read  # symbolic number of bytes read
                return claripy.BVS(f'{gate_name}_default', 32)  # fallback
        return FileModel

    def create_time_model(self, gate_name):
        class TimeModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name == 'time':
                    time_val = claripy.BVS('time_value', 64)
                    self.state.globals['time_value'] = time_val
                    return time_val  # symbolic UNIX timestamp
                elif gate_name == 'gettimeofday':
                    tv_ptr = args[0] if args else None
                    if tv_ptr:
                        sec_val = claripy.BVS('tv_sec', 64)
                        usec_val = claripy.BVS('tv_usec', 64)
                        self.state.memory.store(tv_ptr, sec_val)
                        self.state.memory.store(tv_ptr + 8, usec_val)
                        self.state.globals['tv_sec'] = sec_val
                        self.state.globals['tv_usec'] = usec_val
                    return 0  # success
                return claripy.BVS(f'{gate_name}_time', 64)  # default symbolic time
        return TimeModel

    def create_uid_model(self, gate_name):
        class UidModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                uid_val = claripy.BVS(f'{gate_name}_uid', 32)
                self.state.globals[f'{gate_name}_uid'] = uid_val
                return uid_val  # symbolic UID/GID
        return UidModel

    def create_network_model(self, gate_name):
        class NetworkModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name == 'socket':
                    sock_fd = claripy.BVS('socket_fd', 32)
                    self.state.globals['socket_fd'] = sock_fd
                    return sock_fd  # symbolic socket descriptor
                elif gate_name in ['bind', 'listen', 'connect']:
                    result = claripy.BVS(f'{gate_name}_result', 32)
                    self.state.globals[f'{gate_name}_result'] = result
                    return result  # symbolic return code
                return claripy.BVS(f'{gate_name}_net', 32)  # fallback
        return NetworkModel

    def create_proc_model(self, gate_name):
        class ProcModel(angr.SimProcedure):
            def run(self, *args, **kwargs):
                if gate_name in ['getpid', 'getppid']:
                    pid_val = claripy.BVS(f'{gate_name}_pid', 32)
                    self.state.globals[f'{gate_name}_pid'] = pid_val
                    return pid_val  # symbolic PID
                elif gate_name in ['fork', 'vfork']:
                    fork_result = claripy.BVS(f'{gate_name}_result', 32)
                    self.state.globals[f'{gate_name}_result'] = fork_result
                    return fork_result  # symbolic child PID or error code
                return claripy.BVS(f'{gate_name}_proc', 32)  # fallback
        return ProcModel

class LogicTrapAnalyzer:  # Analyzes basic blocks for logic “traps” based on instruction complexity
    def __init__(self):
        self.complex_operations = {'xor', 'and', 'or', 'not', 'shl', 'shr', 'sar', 'mul', 'imul', 'div', 'idiv', 'mod'}  # heavy arithmetic/bitwise ops
        self.comparison_ops = {'cmp', 'test', 'cmpl', 'testl', 'cmpq', 'testq'}  # comparison instructions
        self.symbolic_ops = {'call', 'callq'}  # call instructions that may hit external gates

    def analyze_block_complexity(self, proj, block_addr: int, gate_addrs: Set[int]) -> Dict[str, Any]:
        try:
            block = proj.factory.block(block_addr)  # lift the block at the given address
            complexity_score = 0  # initialize overall complexity score
            operations = []      # list to record complex operations seen
            comparisons = []     # list to record comparison instructions seen
            gate_calls = []      # list to record calls into external gates
            for insn in block.capstone.insns:  # iterate over each instruction
                mnemonic = insn.mnemonic.lower()  # normalize the opcode name
                if mnemonic in self.complex_operations:
                    complexity_score += 2  # bump score for heavy arithmetic/bitwise
                    operations.append((insn.address, mnemonic, insn.op_str))  # log the op details
                if mnemonic in self.comparison_ops:
                    complexity_score += 1  # bump score for comparisons
                    comparisons.append((insn.address, mnemonic, insn.op_str))  # log comparison details
                if mnemonic.startswith('j') and mnemonic != 'jmp':
                    complexity_score += 1  # bump score for conditional jumps
                if mnemonic in self.symbolic_ops:
                    try:
                        target_addr = int(insn.op_str.split('x')[1], 16) if 'x' in insn.op_str else 0  # parse call target
                        if target_addr in gate_addrs:
                            complexity_score += 3  # bump score for external gate call
                            gate_calls.append((insn.address, mnemonic, insn.op_str))  # log the gate call
                    except:
                        pass  # ignore any parsing errors
            return {
                'score': complexity_score,       # total complexity score
                'operations': operations,        # logged complex operations
                'comparisons': comparisons,      # logged comparisons
                'gate_calls': gate_calls,        # logged external gate calls
                'is_trap': complexity_score >= 3 # classify as trap if score threshold met
            }
        except Exception as e:
            return {'score': 0, 'operations': [], 'comparisons': [], 'gate_calls': [], 'is_trap': False}  # on error, return safe defaults

    def find_logic_traps(self, proj, cfg, gate_addrs: Set[int]) -> List[Tuple[int, Dict[str, Any]]]:
        traps = []  # collect addresses and analyses of identified traps
        print("[+] Re-analyzing logic complexity with gates...")  # notify start of trap search
        for node in cfg.graph.nodes():  # iterate over all CFG nodes
            if hasattr(node, 'addr'):  # ensure the node has a valid address
                analysis = self.analyze_block_complexity(proj, node.addr, gate_addrs)  # analyze this block
                if analysis['is_trap']:
                    traps.append((node.addr, analysis))  # record trap block with its analysis
                    print(f"    Enhanced trap at {hex(node.addr)}: score={analysis['score']}")  # report found trap
                    if analysis['gate_calls']:
                        print(f"      Gate calls: {len(analysis['gate_calls'])}")  # report number of gate calls
        return traps  # return list of all detected traps
class EnhancedShellPayloadAnalyzer:  # Orchestrates payload discovery via symbolic execution and fuzzing
    def __init__(self, binary_path: str, max_input_size: int = 256):
        self.binary_path = binary_path  # path to target binary
        self.max_input_size = max_input_size  # maximum size for generated inputs
        self.proj = None  # angr Project instance placeholder
        self.cfg = None  # control-flow graph placeholder
        self.gate_catalog = ExternalGateCatalog()  # catalog of external function/syscall hooks
        self.dangerous_functions = {'system', 'execve', 'execvp', 'execl', 'execlp', 'execle', 'execv',
                                    'posix_spawn', 'posix_spawnp', 'popen', 'sh', 'bash', 'zsh',
                                    'fork', 'vfork', 'clone', 'waitpid', 'wait', 'wait3', 'wait4'}  # functions indicating shell execution
        self.shell_syscalls = {11: 'execve', 59: 'execve', 57: 'fork', 58: 'vfork', 56: 'clone'}  # syscall numbers mapping
        self.input_functions = {'fgets', 'gets', 'scanf', 'fscanf', 'read', 'fread', 'getline',
                                'getdelim', 'fgetc', 'getchar', 'getc', '__isoc99_scanf'}  # functions reading user input
        self.shell_strings = []  # extracted shell-related strings
        self.system_call_sites = []  # addresses of detected system calls
        self.found_solutions = []  # list of discovered payloads
        self.interesting_strings = []  # non-shell but noteworthy strings
        self.string_xrefs = {}  # cross-references for string usages
        self.symbolic_input = None  # symbolic variable for stdin
        self.system_reached = False  # flag indicating system hook reached
        self.system_addrs = set()  # addresses of system-like functions
        self.solution_states = []  # saved solver states at system call
        self.logic_traps = []  # identified logic trap blocks
        self.payload_scores = []  # stealth scores per payload
        self.successful_payloads = {}  # mapping of addr to payload
        self.logic_analyzer = LogicTrapAnalyzer()  # logic trap detection helper
        self.symbolic_constraints = []  # list of applied input constraints
        self.gate_solutions = {}  # concrete values for gates per state

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
                except:
                    pass
                try:
                    self.proj.hook(gate_addr, self.gate_catalog.symbolic_models[gate_name]())  # hook by address
                    print(f"    Hooked {gate_name} at {hex(gate_addr)}")
                except:
                    pass

    def build_cfg(self) -> bool:
        print("[+] Building CFG with symbolic gates...")  # notify CFG build
        try:
            self.cfg = self.proj.analyses.CFGFast(normalize=True,
                                                  data_references=True,
                                                  resolve_indirect_jumps=True,
                                                  force_complete_scan=False)  # fast CFG
            print(f"[+] CFGFast built with {len(self.cfg.graph.nodes)} nodes")  # report node count
            return True
        except Exception as e:
            print(f"[-] CFGFast failed: {e}")  # report failure
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

    def find_system_calls_enhanced(self) -> List[Tuple[int, str]]:
        system_calls = []  # collect call sites
        print("[+] Enhanced system call detection...")  # notify detection start
        for func_name in self.dangerous_functions:  # check each dangerous function
            try:
                if func_name in self.proj.kb.functions:
                    func = self.proj.kb.functions[func_name]
                    self.system_addrs.add(func.addr)  # log function address
                    print(f"    {func_name} function found at {hex(func.addr)}")
            except:
                pass
            try:
                for addr, name in self.proj.loader.main_object.plt.items():  # scan PLT
                    if name == func_name:
                        self.system_addrs.add(addr)
                        print(f"    {func_name} PLT entry at {hex(addr)}")
            except:
                pass
            try:
                symbol = self.proj.loader.find_symbol(func_name)  # check exported symbols
                if symbol:
                    self.system_addrs.add(symbol.rebased_addr)
                    print(f"    {func_name} symbol at {hex(symbol.rebased_addr)}")
            except:
                pass
        try:
            all_functions = list(self.proj.kb.functions.values())
            for func in all_functions:  # scan every function
                try:
                    for block_addr in func.block_addrs:
                        try:
                            block = self.proj.factory.block(block_addr)  # lift block
                            for insn in block.capstone.insns:  # inspect instructions
                                if insn.mnemonic in ['call', 'callq']:
                                    for dangerous_func in self.dangerous_functions:
                                        if dangerous_func in insn.op_str.lower():
                                            system_calls.append((insn.address, f'{dangerous_func}_call'))  # found call
                                            self.system_call_sites.append(insn.address)
                                            print(f"    FOUND: {dangerous_func} call at {hex(insn.address)}")
                                            break
                                elif insn.mnemonic in ['syscall', 'int', 'sysenter']:
                                    system_calls.append((insn.address, 'syscall'))  # direct syscall
                                    self.system_call_sites.append(insn.address)
                                    print(f"    FOUND: syscall at {hex(insn.address)}")
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception as e:
            print(f"    Error scanning for system calls: {e}")
        return system_calls  # return detected sites

    def create_enhanced_system_hook(self):
        analyzer = self  # capture self for inner class closure
        class EnhancedSystemHook(angr.SimProcedure):
            def run(self, command_ptr=None, *args, **kwargs):
                analyzer.system_reached = True  # mark that system call is reached
                self.state.globals['reached_system'] = True
                self.state.globals['system_addr'] = self.state.addr
                stealth_score = 0  # initialize stealth score
                gate_solutions = {}  # concrete results for gates
                for gate_name in analyzer.gate_catalog.discovered_gates:  # collect gate values
                    gate_key = f'{gate_name}_sym'
                    if gate_key in self.state.globals:
                        sym_val = self.state.globals[gate_key]
                        if analyzer.symbolic_input and self.state.solver.symbolic(sym_val):
                            try:
                                concrete_val = self.state.solver.eval(sym_val)
                                gate_solutions[gate_name] = concrete_val  # record concrete gate output
                                print(f"    Gate {gate_name}: {concrete_val}")
                                stealth_score += 1
                            except:
                                pass
                    for env_key in [k for k in self.state.globals.keys() if k.startswith('env_')]:
                        try:
                            env_val = self.state.globals[env_key]
                            if self.state.solver.symbolic(env_val):
                                concrete_env = self.state.solver.eval(env_val, cast_to=bytes)
                                gate_solutions[env_key] = concrete_env  # record concrete env var
                                print(f"    {env_key}: {concrete_env}")
                                stealth_score += 1
                        except:
                            pass
                for trap_addr, trap_info in analyzer.logic_traps:  # boost score if near a logic trap
                    if abs(self.state.addr - trap_addr) < 100:
                        stealth_score += 3
                        print(f"[!] System call behind enhanced logic trap!")
                        break
                stealth_score += 2  # base score for system hook
                print(f"[!] ENHANCED SYSTEM HOOK at {hex(self.state.addr)} (score: {stealth_score})")
                analyzer.solution_states.append(self.state.copy())  # save state snapshot
                analyzer.payload_scores.append((self.state.addr, stealth_score))
                analyzer.gate_solutions[self.state.addr] = gate_solutions
                try:
                    if 'symbolic_input' in self.state.globals:
                        sym_input = self.state.globals['symbolic_input']
                        try:
                            if self.state.solver.symbolic(sym_input):
                                possible_vals = self.state.solver.eval_upto(sym_input, 8)  # get candidates
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
                        except Exception:
                            pass
                except Exception as e:
                    print(f"[!] Enhanced system hook error: {e}")
                return 0  # override return to avoid real system execution
        return EnhancedSystemHook  # return the hook class

    def setup_hooks(self, system_calls: List[Tuple[int, str]]):
        hook_class = self.create_enhanced_system_hook()  # get hook procedure
        print("[+] Setting up enhanced system hooks...")
        for func_name in self.dangerous_functions:
            try:
                self.proj.hook_symbol(func_name, hook_class())  # hook by symbol
                print(f"    Hooked {func_name} symbol")
            except:
                pass
        hooked_addrs = set()  # track addresses already hooked
        for addr, call_type in system_calls:
            if addr not in hooked_addrs:
                try:
                    self.proj.hook(addr, hook_class())  # hook each call site
                    hooked_addrs.add(addr)
                    print(f"    Hooked {call_type} at {hex(addr)}")
                except:
                    pass
        for system_addr in self.system_addrs:
            if system_addr not in hooked_addrs:
                try:
                    self.proj.hook(system_addr, hook_class())  # hook direct system functions
                    hooked_addrs.add(system_addr)
                    print(f"    Hooked system function at {hex(system_addr)}")
                except:
                    pass

    def add_primary_input_constraints(self, state):
        print("[+] Adding primary input constraints...")
        if 'symbolic_input' in state.globals:
            sym_input = state.globals['symbolic_input']
            input_size = sym_input.size() // 8  # determine byte length
            for i in range(min(input_size, 32)):
                byte_val = sym_input.get_byte(i)
                state.solver.add(claripy.And(byte_val >= 32, byte_val <= 126))  # printable ascii
                self.symbolic_constraints.append(f"byte[{i}] printable")
            if input_size >= 2:  # first two bytes numeric
                byte0 = sym_input.get_byte(0)
                byte1 = sym_input.get_byte(1)
                state.solver.add(claripy.And(byte0 >= 48, byte0 <= 57))
                state.solver.add(claripy.And(byte1 >= 48, byte1 <= 57))
                self.symbolic_constraints.append("first two bytes are digits")

    def guided_symbolic_execution(self, priority_addrs: List[int], input_size: int = 32) -> bool:
        print(f"[+] Running enhanced guided symbolic execution (input size: {input_size})...")
        self.symbolic_input = claripy.BVS('user_input', input_size * 8)  # create symbolic input
        initial_state = self.proj.factory.entry_state(
            stdin=self.symbolic_input,
            add_options={angr.options.LAZY_SOLVES, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
            remove_options={angr.options.SUPPORT_FLOATING_POINT}
        )  # initial execution state
        initial_state.globals['symbolic_input'] = self.symbolic_input
        self.add_primary_input_constraints(initial_state)  # constrain input

        class EnhancedLogicTrapExplorer(angr.exploration_techniques.ExplorationTechnique):
            def __init__(self, trap_addrs, gate_addrs, analyzer):
                super().__init__()
                self.trap_addrs = set(trap_addrs)  # addresses of logic traps
                self.gate_addrs = set(gate_addrs)  # addresses of gates
                self.analyzer = analyzer  # back-reference
            def step(self, simgr, stash='active', **kwargs):
                enhanced_states = []
                normal_states = []
                for state in simgr.stashes.get(stash, []):
                    is_near_trap = any(abs(state.addr - trap_addr) < 50 for trap_addr in self.trap_addrs)
                    is_near_gate = any(abs(state.addr - gate_addr) < 50 for gate_addr in self.gate_addrs)
                    if is_near_trap or is_near_gate:
                        enhanced_states.append(state)  # prioritize states near traps/gates
                    else:
                        normal_states.append(state)
                if enhanced_states:
                    simgr.stashes[stash] = enhanced_states + normal_states[:3]  # keep some normal
                else:
                    simgr.stashes[stash] = normal_states[:8]  # otherwise limit breadth
                return simgr.step(stash=stash, **kwargs)

        simgr = self.proj.factory.simgr(initial_state)  # create simulation manager
        trap_addrs = [addr for addr, _ in self.logic_traps]
        gate_addrs = list(self.gate_catalog.discovered_gates.values())
        simgr.use_technique(EnhancedLogicTrapExplorer(trap_addrs, gate_addrs, self))  # add custom exploration

        try:
            simgr.explore(
                find=lambda s: s.globals.get('reached_system', False),
                avoid=lambda s: s.addr == 0,
                num_find=20,
                step_func=lambda sm: sm if len(sm.active) <= 12 else sm.drop(stash='active', filter_func=lambda s: len(sm.active) - 8)
            )  # run guided exploration

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
                            except:
                                continue
                except Exception as e:
                    print(f"    Error processing found state: {e}")
                    continue
            return len(simgr.found) > 0  # return whether any found
        except Exception as e:
            print(f"[-] Symbolic execution failed: {e}")
            return False

    def clean_solution(self, solution_bytes: bytes) -> str:
        """Clean and validate solution bytes"""
        try:
            for encoding in ['utf-8', 'ascii', 'latin-1']:
                try:
                    decoded = solution_bytes.decode(encoding)  # attempt decode
                    cleaned = ''.join(c for c in decoded if 32 <= ord(c) <= 126)  # filter printable
                    if len(cleaned) > 0:
                        return cleaned
                except:
                    continue
            return solution_bytes.hex()  # fallback to hex representation
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
                except:
                    continue
            except:
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
        system_calls = self.find_system_calls_enhanced()  # gather calls
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