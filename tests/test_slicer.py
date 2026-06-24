"""Unit tests for the gate slicer.

We avoid spinning up real angr Projects (heavy, slow, depend on
binaries). Instead, lightweight stub classes mimic only the surface
the slicer touches: ``cfg.graph.nodes()``, ``cfg.graph.predecessors``,
``proj.factory.block``, ``proj.kb.functions``, ``proj.loader``.
"""
import pytest

from slicer import (
    ExternalCall,
    GateSlice,
    GateSlicer,
)


# --------------------------------------------------------------------- #
# stub helpers
# --------------------------------------------------------------------- #
class _Node:
    def __init__(self, addr: int):
        self.addr = addr

    def __repr__(self):
        return f"<Node {hex(self.addr)}>"


class _Graph:
    def __init__(self, edges):
        # edges: list of (src_addr, dst_addr); each addr becomes a Node.
        addrs = set()
        for src, dst in edges:
            addrs.update((src, dst))
        self._nodes = {a: _Node(a) for a in addrs}
        self._preds: dict = {a: set() for a in addrs}
        for src, dst in edges:
            self._preds[dst].add(src)

    def add_isolated(self, addr: int):
        if addr not in self._nodes:
            self._nodes[addr] = _Node(addr)
            self._preds[addr] = set()

    def nodes(self):
        return list(self._nodes.values())

    def predecessors(self, node):
        addrs = self._preds.get(node.addr, set())
        return [self._nodes[a] for a in addrs]


class _CFG:
    def __init__(self, graph):
        self.graph = graph


# --------------------------------------------------------------------- #
# constructor defaults
# --------------------------------------------------------------------- #
class TestSlicerDefaults:
    def test_uses_env_var_for_ghidra(self, monkeypatch):
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", "/opt/ghidra")
        slicer = GateSlicer()
        assert slicer.ghidra_install_dir == "/opt/ghidra"

    def test_explicit_arg_overrides_env(self, monkeypatch):
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", "/opt/ghidra")
        slicer = GateSlicer(ghidra_install_dir="/usr/local/ghidra")
        assert slicer.ghidra_install_dir == "/usr/local/ghidra"

    def test_empty_string_disables_ghidra(self, monkeypatch):
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        slicer = GateSlicer()
        assert slicer.ghidra_install_dir == ""

    def test_max_hops_floors_at_one(self):
        slicer = GateSlicer(max_slice_hops=0)
        assert slicer.max_slice_hops == 1

    def test_negative_hops_floors_at_one(self):
        slicer = GateSlicer(max_slice_hops=-3)
        assert slicer.max_slice_hops == 1


# --------------------------------------------------------------------- #
# backward walk
# --------------------------------------------------------------------- #
class TestWalkBackward:
    def test_target_only_when_no_predecessors(self):
        cfg = _CFG(_Graph([]))
        cfg.graph.add_isolated(0x1000)
        slicer = GateSlicer(max_slice_hops=5)
        order = slicer._walk_backward(cfg, 0x1000)
        assert order == [0x1000]

    def test_missing_target_falls_back_to_address_only(self):
        cfg = _CFG(_Graph([(0x1000, 0x2000)]))
        slicer = GateSlicer(max_slice_hops=5)
        order = slicer._walk_backward(cfg, 0xDEADBEEF)
        assert order == [0xDEADBEEF]

    def test_collects_chain(self):
        # 0x1000 -> 0x2000 -> 0x3000 (gate)
        cfg = _CFG(_Graph([(0x1000, 0x2000), (0x2000, 0x3000)]))
        slicer = GateSlicer(max_slice_hops=5)
        order = slicer._walk_backward(cfg, 0x3000)
        assert order[0] == 0x3000
        assert set(order) == {0x1000, 0x2000, 0x3000}

    def test_respects_max_hops(self):
        # 0x1000 -> 0x2000 -> 0x3000 -> 0x4000 (gate). With max_slice_hops=1
        # we should only collect the direct predecessor.
        cfg = _CFG(_Graph([(0x1000, 0x2000), (0x2000, 0x3000), (0x3000, 0x4000)]))
        slicer = GateSlicer(max_slice_hops=1)
        order = slicer._walk_backward(cfg, 0x4000)
        assert set(order) == {0x4000, 0x3000}
        assert 0x2000 not in order
        assert 0x1000 not in order

    def test_handles_diamond(self):
        # 0x1000 -> 0x2000
        # 0x1000 -> 0x3000
        # 0x2000 -> 0x4000 (gate)
        # 0x3000 -> 0x4000 (gate)
        cfg = _CFG(_Graph([
            (0x1000, 0x2000),
            (0x1000, 0x3000),
            (0x2000, 0x4000),
            (0x3000, 0x4000),
        ]))
        slicer = GateSlicer(max_slice_hops=5)
        order = slicer._walk_backward(cfg, 0x4000)
        assert set(order) == {0x1000, 0x2000, 0x3000, 0x4000}

    def test_cycle_does_not_loop_forever(self):
        # 0x1000 -> 0x2000 -> 0x1000 cycle, plus 0x2000 -> 0x3000 gate.
        cfg = _CFG(_Graph([
            (0x1000, 0x2000),
            (0x2000, 0x1000),
            (0x2000, 0x3000),
        ]))
        slicer = GateSlicer(max_slice_hops=10)
        order = slicer._walk_backward(cfg, 0x3000)
        # Each node visited at most once.
        assert len(order) == len(set(order))
        assert set(order) == {0x1000, 0x2000, 0x3000}


# --------------------------------------------------------------------- #
# external call resolution
# --------------------------------------------------------------------- #
class _StubFunc:
    def __init__(self, name):
        self.name = name


class _StubFunctions:
    def __init__(self, mapping):
        self._mapping = mapping  # {addr: name}

    def __contains__(self, addr):
        return addr in self._mapping

    def __getitem__(self, addr):
        return _StubFunc(self._mapping[addr])


class _StubKB:
    def __init__(self, functions=None):
        self.functions = _StubFunctions(functions or {})


class _StubPLT:
    def __init__(self, mapping):
        self._mapping = mapping  # {addr: name}

    def items(self):
        return list(self._mapping.items())


class _StubMainObject:
    def __init__(self, plt=None):
        self.plt = _StubPLT(plt or {})


class _StubLoader:
    def __init__(self, plt=None, symbols=None):
        self.main_object = _StubMainObject(plt=plt or {})
        self._symbols = symbols or {}

    def find_symbol(self, name):
        s = self._symbols.get(name)
        return s


class _Symbol:
    def __init__(self, name):
        self.name = name


class _StubProj:
    def __init__(self, functions=None, plt=None, symbols=None):
        self.kb = _StubKB(functions=functions)
        self.loader = _StubLoader(plt=plt, symbols=symbols)


class TestResolveCallTarget:
    def test_hex_addr_resolves_via_kb_functions(self):
        proj = _StubProj(functions={0x401234: "system"})
        assert GateSlicer._resolve_call_target(proj, "0x401234") == "system"

    def test_hex_addr_resolves_via_plt(self):
        proj = _StubProj(plt={0x402000: "getenv"})
        assert GateSlicer._resolve_call_target(proj, "0x402000") == "getenv"

    def test_unknown_hex_addr_returns_none(self):
        proj = _StubProj()
        assert GateSlicer._resolve_call_target(proj, "0x99999") is None

    def test_symbol_name_resolved_via_loader(self):
        proj = _StubProj(symbols={"execve": _Symbol("execve")})
        assert GateSlicer._resolve_call_target(proj, "execve") == "execve"

    def test_register_or_unknown_string_returns_none(self):
        proj = _StubProj()
        assert GateSlicer._resolve_call_target(proj, "rax") is None
        assert GateSlicer._resolve_call_target(proj, "") is None


# --------------------------------------------------------------------- #
# Ghidra fallback
# --------------------------------------------------------------------- #
class TestGhidraFallback:
    def test_no_install_dir_returns_empty(self, monkeypatch):
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        slicer = GateSlicer()
        assert slicer._try_ghidra(proj=object(), block_addrs=[0x1000]) == ""

    def test_missing_executable_returns_empty(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
        slicer = GateSlicer()
        # support/analyzeHeadless does not exist in tmp_path -> graceful empty.
        assert slicer._try_ghidra(proj=object(), block_addrs=[0x1000]) == ""

    def test_executable_path_under_install_dir(self, tmp_path):
        slicer = GateSlicer(ghidra_install_dir=str(tmp_path))
        path = slicer._ghidra_headless_executable()
        # The basename must be the headless analyzer; extension depends on host OS.
        assert "analyzeHeadless" in path
        # The full path must live under the configured install dir's support/ subdir.
        assert str(tmp_path) in path
        assert ("support" + ("\\" if "\\" in path else "/")) in path

    def test_executable_path_empty_when_no_install_dir(self):
        slicer = GateSlicer(ghidra_install_dir="")
        assert slicer._ghidra_headless_executable() == ""


# --------------------------------------------------------------------- #
# dataclass smoke
# --------------------------------------------------------------------- #
class TestDataclassDefaults:
    def test_external_call_minimal_construction(self):
        c = ExternalCall(addr=0x401000, target_name="getenv")
        assert c.args == []

    def test_gate_slice_minimal_construction(self):
        s = GateSlice(gate_addr=0x401000, sink_addr=0x402000)
        assert s.slice_blocks == []
        assert s.vex_ir == ""
        assert s.pseudo_c == ""
        assert s.external_calls == []
