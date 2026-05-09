from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
from typing import Any

from .models import new_id, to_primitive, utc_now


@dataclass(frozen=True)
class ProvenanceNode:
    node_id: str
    node_type: str
    trace_id: str
    attributes: dict[str, Any]
    created_at: str


@dataclass(frozen=True)
class ProvenanceEdge:
    edge_id: str
    source: str
    target: str
    relation: str
    trace_id: str
    attributes: dict[str, Any]
    created_at: str


class ProvenanceGraph:
    """Mutable graph projection built from append-only event lineage."""

    def __init__(self, graph_path: str | Path) -> None:
        self.path = Path(graph_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(
                json.dumps({"nodes": {}, "edges": []}, indent=2),
                encoding="utf-8",
            )
        self._state = json.loads(self.path.read_text(encoding="utf-8"))

    def upsert_node(
        self,
        node_id: str,
        node_type: str,
        trace_id: str,
        attributes: dict[str, Any],
    ) -> ProvenanceNode:
        node = ProvenanceNode(
            node_id=node_id,
            node_type=node_type,
            trace_id=trace_id,
            attributes=attributes,
            created_at=utc_now(),
        )
        self._state["nodes"][node_id] = to_primitive(node)
        self._save()
        return node

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        trace_id: str,
        attributes: dict[str, Any] | None = None,
    ) -> ProvenanceEdge:
        if source not in self._state["nodes"] or target not in self._state["nodes"]:
            raise ValueError("source and target nodes must exist")

        edge = ProvenanceEdge(
            edge_id=new_id("edge"),
            source=source,
            target=target,
            relation=relation,
            trace_id=trace_id,
            attributes=attributes or {},
            created_at=utc_now(),
        )
        self._state["edges"].append(to_primitive(edge))
        self._save()
        return edge

    def trace_projection(self, trace_id: str) -> dict[str, Any]:
        nodes = {
            node_id: node
            for node_id, node in self._state["nodes"].items()
            if node["trace_id"] == trace_id
        }
        edges = [edge for edge in self._state["edges"] if edge["trace_id"] == trace_id]
        return {"nodes": nodes, "edges": edges}

    def artifact_lineage(self, artifact_id: str) -> dict[str, Any]:
        if artifact_id not in self._state["nodes"]:
            return {"nodes": {}, "edges": []}

        visited: set[str] = set()
        stack: list[str] = [artifact_id]
        lineage_edges: list[dict[str, Any]] = []

        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)

            for edge in self._state["edges"]:
                if edge["target"] == current and edge["source"] not in visited:
                    lineage_edges.append(edge)
                    stack.append(edge["source"])

        lineage_nodes = {
            node_id: self._state["nodes"][node_id]
            for node_id in visited
            if node_id in self._state["nodes"]
        }
        return {"nodes": lineage_nodes, "edges": lineage_edges}

    def _save(self) -> None:
        temp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        temp_path.write_text(
            json.dumps(self._state, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        temp_path.replace(self.path)
