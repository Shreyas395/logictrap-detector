"""Unit tests for the external-gate catalog default state."""
import pytest

from external_gates import ExternalGateCatalog


@pytest.fixture
def catalog():
    return ExternalGateCatalog()


class TestCategorySets:
    @pytest.mark.parametrize("attr", [
        "randomness_gates",
        "env_gates",
        "file_gates",
        "time_gates",
        "uid_gates",
        "network_gates",
        "proc_gates",
    ])
    def test_category_is_nonempty(self, catalog, attr):
        assert getattr(catalog, attr), f"{attr} should not be empty"

    @pytest.mark.parametrize("gate,attr", [
        ("rand", "randomness_gates"),
        ("getenv", "env_gates"),
        ("open", "file_gates"),
        ("time", "time_gates"),
        ("getuid", "uid_gates"),
        ("socket", "network_gates"),
        ("fork", "proc_gates"),
    ])
    def test_category_contains_representative(self, catalog, gate, attr):
        assert gate in getattr(catalog, attr)


class TestAllGatesUnion:
    def test_all_gates_is_union_of_categories(self, catalog):
        expected = (
            catalog.randomness_gates
            | catalog.env_gates
            | catalog.file_gates
            | catalog.time_gates
            | catalog.uid_gates
            | catalog.network_gates
            | catalog.proc_gates
        )
        assert catalog.all_gates == expected

    def test_all_gates_size_is_sum_of_categories(self, catalog):
        # Categories must be disjoint for this equality to hold; if a
        # future change makes them overlap, this test will surface it.
        total = sum(
            len(getattr(catalog, attr))
            for attr in (
                "randomness_gates", "env_gates", "file_gates",
                "time_gates", "uid_gates", "network_gates", "proc_gates",
            )
        )
        assert len(catalog.all_gates) == total


class TestDiscoveryAndModelsStartEmpty:
    def test_discovered_gates_starts_empty(self, catalog):
        assert catalog.discovered_gates == {}

    def test_symbolic_models_starts_empty(self, catalog):
        assert catalog.symbolic_models == {}
