"""External-dependency gate catalog and symbolic models.

Models environment, time, randomness, file I/O, network, UID, and process
syscalls so symbolic execution doesn't bail when a path depends on them.
Used by the orchestrator to install SimProcedure hooks before exploration.
"""
import logging

import angr
import claripy

log = logging.getLogger(__name__)


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
            except Exception as e:
                log.debug(f"kb.functions lookup failed for {gate}: {e}")
            try:
                for addr, name in proj.loader.main_object.plt.items():
                    if name == gate:
                        self.discovered_gates[gate] = addr
                        print(f"    {gate} PLT at {hex(addr)}")
            except Exception as e:
                log.debug(f"PLT scan failed for {gate}: {e}")
            try:
                symbol = proj.loader.find_symbol(gate)
                if symbol:
                    self.discovered_gates[gate] = symbol.rebased_addr
                    print(f"    {gate} symbol at {hex(symbol.rebased_addr)}")
            except Exception as e:
                log.debug(f"find_symbol failed for {gate}: {e}")
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
                        except Exception:
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
