"""Sink-distance scorer.

Replaces the original ad-hoc "stealth score" with a defined metric so the
paper has a calibratable knob:

    score = (gate_complexity * external_dep_count) / max(1, basic_blocks_to_sink)

Higher = the gate is more "loaded" (lots of obfuscation + many external
dependencies) AND sits closer to a sink. Reviewer-defensible because every
term has a clear interpretation.
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class GateScore:
    gate_addr: int
    sink_addr: int
    gate_complexity: int
    external_dep_count: int
    basic_blocks_to_sink: int
    score: float


class SinkDistanceScorer:
    def score(
        self,
        gate_addr: int,
        sink_addr: int,
        gate_complexity: int,
        external_dep_count: int,
        basic_blocks_to_sink: int,
    ) -> GateScore:
        bb = max(1, basic_blocks_to_sink)
        value = (gate_complexity * external_dep_count) / bb
        return GateScore(
            gate_addr=gate_addr,
            sink_addr=sink_addr,
            gate_complexity=gate_complexity,
            external_dep_count=external_dep_count,
            basic_blocks_to_sink=bb,
            score=value,
        )

    @staticmethod
    def basic_blocks_between(cfg, src_addr: int, dst_addr: int) -> int:
        """Shortest-path distance in basic blocks between two addresses in the CFG.

        Returns a large sentinel (999) if no path exists, so the score
        degrades gracefully toward 0 instead of throwing.
        """
        try:
            import networkx as nx
            src_node = None
            dst_node = None
            for node in cfg.graph.nodes():
                if not hasattr(node, 'addr'):
                    continue
                if node.addr == src_addr:
                    src_node = node
                if node.addr == dst_addr:
                    dst_node = node
            if src_node is None or dst_node is None:
                return 999
            try:
                return nx.shortest_path_length(cfg.graph, src_node, dst_node)
            except nx.NetworkXNoPath:
                return 999
            except nx.NodeNotFound:
                return 999
        except Exception:
            return 999
