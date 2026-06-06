"""Unit tests for SinkFinder and LogicTrapAnalyzer defaults."""
import pytest

from gate_locator import (
    DEFAULT_CALL_MNEMONICS,
    DEFAULT_DANGEROUS_FUNCTIONS,
    DEFAULT_DIRECT_SYSCALL_MNEMONICS,
    LogicTrapAnalyzer,
    SinkFinder,
)


class TestSinkFinderDefaults:
    def test_default_dangerous_functions_includes_classic_sinks(self):
        finder = SinkFinder()
        for name in ("system", "execve", "execvp", "popen", "fork"):
            assert name in finder.dangerous_functions

    def test_default_call_mnemonics(self):
        finder = SinkFinder()
        assert "call" in finder.call_mnemonics
        assert "callq" in finder.call_mnemonics

    def test_default_direct_syscall_mnemonics(self):
        finder = SinkFinder()
        assert "syscall" in finder.direct_syscall_mnemonics
        assert "int" in finder.direct_syscall_mnemonics
        assert "sysenter" in finder.direct_syscall_mnemonics

    def test_addrs_and_sites_start_empty(self):
        finder = SinkFinder()
        assert finder.system_addrs == set()
        assert finder.system_call_sites == []

    def test_custom_dangerous_functions_override_defaults(self):
        custom = {"my_dangerous_func"}
        finder = SinkFinder(dangerous_functions=custom)
        assert finder.dangerous_functions == custom
        assert "system" not in finder.dangerous_functions

    def test_constructor_copies_inputs(self):
        """Mutating the input collection after construction must not leak in."""
        source = {"my_func"}
        finder = SinkFinder(dangerous_functions=source)
        source.add("sneaky_addition")
        assert "sneaky_addition" not in finder.dangerous_functions


class TestSinkFinderDefaultsExposedAsModuleConstants:
    """The orchestrator and tests can re-use the defaults without
    re-instantiating; lock those constants down so a future refactor
    doesn't quietly drop a sink kind from the catalog."""

    def test_module_level_defaults_match_constructor(self):
        finder = SinkFinder()
        assert finder.dangerous_functions == set(DEFAULT_DANGEROUS_FUNCTIONS)
        assert finder.call_mnemonics == set(DEFAULT_CALL_MNEMONICS)
        assert finder.direct_syscall_mnemonics == set(DEFAULT_DIRECT_SYSCALL_MNEMONICS)


class TestLogicTrapAnalyzerDefaults:
    @pytest.fixture
    def analyzer(self):
        return LogicTrapAnalyzer()

    def test_complex_operations_include_bitwise(self, analyzer):
        for op in ("xor", "and", "or", "shl", "shr"):
            assert op in analyzer.complex_operations

    def test_complex_operations_include_arithmetic(self, analyzer):
        for op in ("mul", "imul", "div", "idiv"):
            assert op in analyzer.complex_operations

    def test_comparison_ops_include_cmp_variants(self, analyzer):
        for op in ("cmp", "test", "cmpl", "cmpq"):
            assert op in analyzer.comparison_ops

    def test_symbolic_ops_are_calls(self, analyzer):
        assert analyzer.symbolic_ops == {"call", "callq"}


class TestAnalyzeBlockComplexityFailsSafe:
    """``analyze_block_complexity`` swallows analysis errors and returns
    a zero-score record so an unanalyzable block doesn't stop the
    overall sweep. Verify the safe-default shape."""

    def test_returns_safe_default_on_invalid_proj(self):
        """No real angr project — the lift will throw and the helper
        should hand back a sentinel record."""
        analyzer = LogicTrapAnalyzer()
        result = analyzer.analyze_block_complexity(
            proj=None,
            block_addr=0xDEADBEEF,
            gate_addrs=set(),
        )
        assert result["score"] == 0
        assert result["is_trap"] is False
        assert result["operations"] == []
        assert result["comparisons"] == []
        assert result["gate_calls"] == []
