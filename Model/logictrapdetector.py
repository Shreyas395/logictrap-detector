#!/usr/bin/env python3

import angr
import claripy
import sys
import os
import logging
import time
import re
from typing import List, Tuple, Optional, Set, Dict

logging.getLogger('angr').setLevel(logging.WARNING)
logging.getLogger('claripy').setLevel(logging.WARNING)

class EnhancedShellPayloadAnalyzer:
    def __init__(self, binary_path: str, max_input_size: int = 256):
        self.binary_path = binary_path
        self.max_input_size = max_input_size
        self.proj = None
        self.cfg = None
        self.dangerous_functions = {
            'system', 'execve', 'execvp', 'execl', 'execlp', 'execle', 'execv',
            'posix_spawn', 'posix_spawnp', 'popen', 'sh', 'bash'
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
        
    def load_binary(self) -> bool:
        """Load the binary and perform initial analysis."""
        try:
            self.proj = angr.Project(self.binary_path, auto_load_libs=True, 
                                   load_options={'main_opts': {'base_addr': 0}})
            print(f"[+] Loaded binary: {self.binary_path}")
            print(f"[+] Architecture: {self.proj.arch}")
            print(f"[+] Entry point: {hex(self.proj.entry)}")
            return True
        except Exception as e:
            print(f"[-] Failed to load binary: {e}")
            return False
    
    def build_cfg(self) -> bool:
        """Build control flow graph with multiple strategies."""
        print("[+] Building CFG...")
        
        try:
            self.cfg = self.proj.analyses.CFGFast(
                normalize=True,
                force_complete_scan=True,
                collect_data_references=True,
                data_references=True
            )
            print(f"[+] CFGFast built with {len(self.cfg.graph.nodes)} nodes")
            return True
        except Exception as e:
            print(f"[-] CFGFast failed: {e}")
            return False
    
    def find_shell_strings(self) -> List[Tuple[int, str]]:
        """Find all shell-related strings in the binary."""
        print("[+] Finding shell-related strings...")
        
        shell_patterns = [
            r'/bin/sh', r'/bin/bash', r'sh\s*$', r'bash\s*$',
            r'system\s*\(', r'exec[lv]', r'cmd\.exe', r'powershell',
            r'shell', r'whoami', r'id\s*$', r'cat\s+', r'ls\s+',
            r'/usr/bin/', r'/sbin/', r'nc\s+', r'netcat'
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
    
    def find_string_references(self):
        """Find cross-references to interesting strings (optimized)."""
        print("[+] Finding string cross-references (quick scan)...")
        
        shell_addrs = [addr for addr, string in self.shell_strings]
        
        if not shell_addrs:
            print("    No shell strings to check references for")
            return
            
        key_functions = ['main']
        nodes_to_check = []
        
        for func_name in key_functions:
            try:
                func = self.proj.kb.functions.get(func_name)
                if func:
                    for block_addr in func.block_addrs:
                        for node in self.cfg.graph.nodes:
                            if hasattr(node, 'addr') and node.addr == block_addr:
                                nodes_to_check.append(node)
                                break
            except:
                continue
        
        if not nodes_to_check:
            nodes_to_check = list(self.cfg.graph.nodes)[:100]
        
        print(f"    Checking {len(nodes_to_check)} nodes for string references...")
        
        for addr, string in self.shell_strings:
            xrefs = []
            
            for node in nodes_to_check:
                try:
                    if hasattr(node, 'addr') and node.addr:
                        block = self.proj.factory.block(node.addr)
                        
                        for insn in block.capstone.insns:
                            if hex(addr)[2:] in insn.op_str:
                                xrefs.append(insn.address)
                                print(f"    String '{string}' possibly referenced at {hex(insn.address)}")
                                            
                except Exception:
                    continue
            
            if xrefs:
                self.string_xrefs[addr] = (string, xrefs)
    
    def find_system_calls_enhanced(self) -> List[Tuple[int, str]]:
        """Enhanced system call detection (optimized)."""
        system_calls = []
        
        print("[+] Enhanced system call detection (quick scan)...")
        
        system_addrs = set()
        
        try:
            if 'system' in self.proj.kb.functions:
                func = self.proj.kb.functions['system']
                system_addrs.add(func.addr)
                print(f"    System function found at {hex(func.addr)}")
        except:
            pass
        
        try:
            for addr, name in self.proj.loader.main_object.plt.items():
                if name == 'system':
                    system_addrs.add(addr)
                    print(f"    System PLT entry at {hex(addr)}")
        except:
            pass
        
        try:
            system_symbol = self.proj.loader.find_symbol('system')
            if system_symbol:
                system_addrs.add(system_symbol.rebased_addr)
                print(f"    System symbol at {hex(system_symbol.rebased_addr)}")
        except:
            pass
        
        if not system_addrs:
            print("[-] No system function addresses found")
            return []
        
        print("[+] Scanning main function for calls...")
        
        nodes_to_scan = []
        
        try:
            main_func = self.proj.kb.functions.get('main')
            if main_func:
                print(f"    Scanning main function at {hex(main_func.addr)}")
                for block_addr in main_func.block_addrs:
                    for node in self.cfg.graph.nodes:
                        if hasattr(node, 'addr') and node.addr == block_addr:
                            nodes_to_scan.append(node)
                            break
        except:
            pass
        
        if not nodes_to_scan:
            nodes_to_scan = list(self.cfg.graph.nodes)[:50]
        
        call_count = 0
        for node in nodes_to_scan:
            try:
                if hasattr(node, 'addr') and node.addr:
                    block = self.proj.factory.block(node.addr)
                    
                    for insn in block.capstone.insns:
                        if insn.mnemonic in ['call', 'callq']:
                            call_count += 1
                            
                            if 'system' in insn.op_str or any(hex(addr)[2:] in insn.op_str for addr in system_addrs):
                                system_calls.append((insn.address, 'detected_call'))
                                self.system_call_sites.append(insn.address)
                                print(f"    FOUND: System call at {hex(insn.address)}: {insn.op_str}")
                            
                            if call_count <= 10:
                                print(f"    Call at {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                                
            except Exception as e:
                continue
        
        print(f"[+] Scanned {call_count} call instructions in key functions")
        return system_calls
    
    def create_enhanced_system_hook(self):
        """Enhanced system hook that captures more information."""
        class EnhancedSystemHook(angr.SimProcedure):
            def run(self, command_ptr):
                self.state.globals['reached_system'] = True
                self.state.globals['system_addr'] = self.state.addr
                
                print(f"[!] SYSTEM HOOK TRIGGERED at {hex(self.state.addr)}")
                
                try:
                    if self.state.solver.symbolic(command_ptr):
                        self.state.globals['symbolic_command'] = True
                        print(f"[!] System called with SYMBOLIC command!")
                        
                        try:
                            example_vals = self.state.solver.eval_upto(command_ptr, 5)
                            for val in example_vals:
                                try:
                                    if val != 0:
                                        cmd_bytes = self.state.mem[val].string.concrete
                                        cmd_str = cmd_bytes.decode('utf-8', errors='ignore')
                                        print(f"    Possible command: '{cmd_str}'")
                                except:
                                    pass
                        except:
                            pass
                    else:
                        try:
                            cmd_str = self.state.mem[command_ptr].string.concrete.decode('utf-8', errors='ignore')
                            self.state.globals['command_string'] = cmd_str
                            print(f"[!] System called with concrete command: '{cmd_str}'")
                        except Exception as e:
                            print(f"[!] System called but couldn't decode command: {e}")
                            
                except Exception as e:
                    print(f"[!] System hook error: {e}")
                
                return 0
                
        return EnhancedSystemHook
    
    def setup_comprehensive_hooks(self, system_calls: List[Tuple[int, str]]):
        """Set up comprehensive hooks for system calls."""
        hook_class = self.create_enhanced_system_hook()
        
        print("[+] Setting up comprehensive system hooks...")
        
        try:
            self.proj.hook_symbol('system', hook_class())
            print("    Hooked system symbol")
        except Exception as e:
            print(f"    Failed to hook system symbol: {e}")
        
        hooked_addrs = set()
        for addr, call_type in system_calls:
            if addr not in hooked_addrs:
                try:
                    self.proj.hook(addr, hook_class())
                    hooked_addrs.add(addr)
                    print(f"    Hooked {call_type} at {hex(addr)}")
                except Exception as e:
                    print(f"    Failed to hook {call_type} at {hex(addr)}: {e}")
        
        for str_addr, (string, xrefs) in self.string_xrefs.items():
            if any(keyword in string.lower() for keyword in ['sh', 'bash', 'system']):
                for xref_addr in xrefs:
                    if xref_addr not in hooked_addrs:
                        try:
                            self.proj.hook(xref_addr, hook_class())
                            hooked_addrs.add(xref_addr)
                            print(f"    Hooked string reference at {hex(xref_addr)} for '{string}'")
                        except:
                            pass
    
    def run_targeted_symbolic_execution(self, target_addrs: List[int], input_size: int = 50) -> bool:
        """Run symbolic execution targeting specific addresses (optimized)."""
        print(f"[+] Quick targeted symbolic execution...")
        
        if not target_addrs:
            print("    No target addresses provided")
            return False
        
        sym_input = claripy.BVS('user_input', input_size * 8)
        stdin_file = angr.storage.SimFile('stdin', content=sym_input, size=input_size)
        
        initial_state = self.proj.factory.entry_state(
            stdin=stdin_file,
            add_options={
                angr.options.LAZY_SOLVES,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            }
        )
        
        simgr = self.proj.factory.simgr(initial_state)
        
        target_set = set(target_addrs[:5])
        print(f"    Targeting: {[hex(addr) for addr in target_set]}")
        
        try:
            simgr.explore(
                find=lambda s: s.addr in target_set or s.globals.get('reached_system', False),
                avoid=[],
                step_func=lambda sm: sm if len(sm.active) < 20 else sm.prune(),
                num_find=3,
                max_steps=100
            )
            
            solutions = []
            
            for state in simgr.found:
                print(f"[+] Found target state at {hex(state.addr)}!")
                try:
                    solution = state.solver.eval(sym_input, cast_to=bytes)
                    clean_sol = self.clean_solution(solution)
                    if clean_sol:
                        solutions.append(clean_sol)
                        print(f"[+] Solution: '{clean_sol}'")
                except Exception as e:
                    print(f"[-] Error extracting solution: {e}")
            
            self.found_solutions.extend(solutions)
            return len(solutions) > 0
            
        except Exception as e:
            print(f"[-] Targeted exploration failed: {e}")
            return False
    
    def run_brute_force_inputs(self) -> bool:
        """Try common shell payload inputs (quick test)."""
        print("[+] Trying common shell payloads (quick test)...")
        
        common_payloads = [
            "/bin/sh",
            "sh", 
            "admin",
            "test",
            "password",
            "secret"
        ]
        
        solutions = []
        
        for payload in common_payloads:
            print(f"    Trying payload: '{payload}'")
            
            try:
                concrete_input = payload.encode() + b'\n\x00'
                stdin_file = angr.storage.SimFile('stdin', content=concrete_input, size=len(concrete_input))
                
                state = self.proj.factory.entry_state(
                    stdin=stdin_file,
                    add_options={angr.options.LAZY_SOLVES}
                )
                simgr = self.proj.factory.simgr(state)
                
                steps = 0
                max_steps = 20
                
                while steps < max_steps and simgr.active:
                    steps += 1
                    
                    for st in simgr.active:
                        if st.globals.get('reached_system', False):
                            solutions.append(payload)
                            print(f"[+] SUCCESS: Payload '{payload}' triggered system call!")
                            break
                    
                    if payload in solutions:
                        break
                    
                    try:
                        simgr.step()
                    except:
                        break
                    
                    if len(simgr.active) > 10:
                        simgr.active = simgr.active[:10]
                        
            except Exception as e:
                print(f"    Error with payload '{payload}': {e}")
                continue
        
        self.found_solutions.extend(solutions)
        return len(solutions) > 0
    
    def clean_solution(self, raw_solution: bytes) -> Optional[str]:
        """Clean and format the solution."""
        try:
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
            return cleaned if len(cleaned) > 0 else None
            
        except Exception:
            return None
    
    def analyze_program_flow(self):
        """Analyze program flow to understand how to reach system calls (quick analysis)."""
        print("\n[+] Quick program flow analysis...")
        
        input_checks = []
        
        try:
            main_func = self.proj.kb.functions.get('main')
            if main_func:
                print(f"    Main function: {hex(main_func.addr)} (size: {main_func.size})")
                
                try:
                    block = self.proj.factory.block(main_func.addr, size=min(main_func.size, 200))
                    print("    Key instructions in main:")
                    
                    insn_count = 0
                    for insn in block.capstone.insns:
                        insn_count += 1
                        if insn_count > 15:
                            print("      ... (truncated)")
                            break
                            
                        print(f"      {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                        
                        if insn.mnemonic in ['cmp', 'test']:
                            print(f"        ^ Comparison - might check input")
                            input_checks.append(insn.address)
                        elif insn.mnemonic in ['call', 'callq']:
                            print(f"        ^ Function call")
                            if 'system' in insn.op_str:
                                print(f"        ^ SYSTEM CALL FOUND!")
                        elif any(func in insn.op_str for func in ['scanf', 'fgets', 'gets']):
                            print(f"        ^ Input function")
                            
                except Exception as e:
                    print(f"    Error disassembling main: {e}")
                    
        except Exception as e:
            print(f"    Error analyzing main function: {e}")
        
        return input_checks
    
    def run_full_analysis(self) -> bool:
        """Run the complete enhanced analysis."""
        print("=" * 80)
        print("ENHANCED SHELL PAYLOAD ANALYZER")
        print("=" * 80)
        
        if not self.load_binary():
            return False
        
        if not self.build_cfg():
            return False
        
        shell_strings = self.find_shell_strings()
        
        self.find_string_references()
        
        system_calls = self.find_system_calls_enhanced()
        
        input_checks = self.analyze_program_flow()
        
        print(f"\n[+] Analysis Summary:")
        print(f"    Shell strings: {len(shell_strings)}")
        print(f"    System calls: {len(system_calls)}")
        print(f"    Input checks: {len(input_checks)}")
        
        if not system_calls and not shell_strings:
            print("[-] No system calls or shell strings found!")
            return False
        
        self.setup_comprehensive_hooks(system_calls)
        
        print("\n" + "=" * 50)
        print("RUNNING MULTIPLE ANALYSIS APPROACHES")
        print("=" * 50)
        
        success = False
        
        if self.run_brute_force_inputs():
            success = True
        
        if system_calls:
            target_addrs = [addr for addr, _ in system_calls]
            if self.run_targeted_symbolic_execution(target_addrs):
                success = True
        
        if input_checks:
            if self.run_targeted_symbolic_execution(input_checks):
                success = True
        
        print("\n" + "=" * 80)
        if success and self.found_solutions:
            print(f"ANALYSIS COMPLETED - FOUND {len(self.found_solutions)} SOLUTIONS")
            print("=" * 80)
            print("\nSHELL PAYLOAD INPUTS:")
            for i, solution in enumerate(set(self.found_solutions), 1):
                print(f"  {i}. '{solution}'")
                
            if self.shell_strings:
                print(f"\nSHELL STRINGS FOUND IN BINARY:")
                for addr, string in self.shell_strings:
                    print(f"  {hex(addr)}: '{string}'")
        else:
            print("ANALYSIS COMPLETED - NO SOLUTIONS FOUND")
            print("=" * 80)
            
            if self.shell_strings:
                print(f"\nHowever, found {len(self.shell_strings)} shell strings:")
                for addr, string in self.shell_strings:
                    print(f"  {hex(addr)}: '{string}'")
                print("\nThis suggests the binary contains shell payloads but may require")
                print("more complex input patterns or specific conditions to trigger them.")
        
        return success


def main():
    if len(sys.argv) != 2:
        print("Usage: python enhanced_analyzer.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    if not os.path.exists(binary_path):
        print(f"Binary not found: {binary_path}")
        sys.exit(1)
    
    analyzer = EnhancedShellPayloadAnalyzer(binary_path)
    success = analyzer.run_full_analysis()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()