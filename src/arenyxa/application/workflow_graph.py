"""Original Arenyxa workflow graph model, validation, editing, and topology layout."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping


@dataclass(slots=True)
class GraphNode:
    """Positioned workflow node in an Arenyxa visual graph layout."""
    id: str
    kind: str
    lane: int
    index: int
    x: int
    y: int
    next_ids: list[str]
    failure_ids: list[str]
    config: dict[str, Any]


@dataclass(slots=True)
class GraphEdge:
    """Typed connection between workflow nodes."""
    source: str
    target: str
    edge_type: str


class WorkflowGraphModel:
    """Validated bounded DAG model shared by the visual graph and raw workflow JSON."""
    MAX_NODES = 1000
    MAX_EDGES = 10000
    LANE_WIDTH = 240
    ROW_HEIGHT = 120

    def __init__(self, payload: Mapping[str, Any]) -> None:
        self.payload = self._normalize_payload(payload)
        self._validate()

    @classmethod
    def _normalize_payload(cls, payload: Mapping[str, Any]) -> dict[str, Any]:
        rows = payload.get("nodes")
        if not isinstance(rows, list):
            raise ValueError("Workflow nodes must be a list")
        if len(rows) > cls.MAX_NODES:
            raise ValueError("Workflow graph exceeds the node budget")
        nodes: list[dict[str, Any]] = []
        for raw in rows:
            if not isinstance(raw, Mapping):
                continue
            nodes.append({
                "id": str(raw.get("id") or "").strip(),
                "kind": str(raw.get("kind") or "").strip(),
                "config": dict(raw.get("config") or {}),
                "next_ids": [str(item) for item in list(raw.get("next_ids") or [])[:256]],
                "failure_ids": [str(item) for item in list(raw.get("failure_ids") or [])[:256]],
            })
        return {
            "schema": str(payload.get("schema") or "arenyxa.workflow/v1")[:128],
            "name": str(payload.get("name") or "Workflow")[:256],
            "id": str(payload.get("id") or ""),
            "version": str(payload.get("version") or "1.0.0"),
            "metadata": dict(payload.get("metadata") or {}),
            "nodes": nodes,
        }

    def _validate(self) -> None:
        nodes = list(self.payload["nodes"])
        ids = [str(row["id"]) for row in nodes]
        if any(not item for item in ids):
            raise ValueError("Workflow node IDs must be non-empty")
        if len(ids) != len(set(ids)):
            raise ValueError("Workflow node IDs must be unique")
        known = set(ids)
        edge_count = 0
        for row in nodes:
            if not row["kind"]:
                raise ValueError(f"Workflow node {row['id']} has no kind")
            for target in [*row["next_ids"], *row["failure_ids"]]:
                edge_count += 1
                if target not in known:
                    raise ValueError(f"Workflow node {row['id']} references missing node {target}")
        if edge_count > self.MAX_EDGES:
            raise ValueError("Workflow graph exceeds the edge budget")
        self._topological_levels(raise_on_cycle=True)

    def snapshot(self) -> dict[str, Any]:
        return {
            "schema": self.payload["schema"],
            "name": self.payload["name"],
            "id": self.payload["id"],
            "version": self.payload["version"],
            "metadata": dict(self.payload["metadata"]),
            "nodes": [
                {
                    "id": row["id"],
                    "kind": row["kind"],
                    "config": dict(row["config"]),
                    "next_ids": list(row["next_ids"]),
                    "failure_ids": list(row["failure_ids"]),
                }
                for row in self.payload["nodes"]
            ],
        }

    def layout(self) -> dict[str, Any]:
        levels = self._topological_levels(raise_on_cycle=False)
        lane_rows: dict[int, list[str]] = {}
        for row in self.payload["nodes"]:
            lane_rows.setdefault(levels.get(row["id"], 0), []).append(row["id"])
        nodes: list[GraphNode] = []
        by_id = {row["id"]: row for row in self.payload["nodes"]}
        for lane in sorted(lane_rows):
            for index, node_id in enumerate(lane_rows[lane]):
                row = by_id[node_id]
                nodes.append(GraphNode(
                    id=node_id,
                    kind=row["kind"],
                    lane=lane,
                    index=index,
                    x=40 + lane * self.LANE_WIDTH,
                    y=40 + index * self.ROW_HEIGHT,
                    next_ids=list(row["next_ids"]),
                    failure_ids=list(row["failure_ids"]),
                    config=dict(row["config"]),
                ))
        edges = [
            GraphEdge(row["id"], target, "normal")
            for row in self.payload["nodes"]
            for target in row["next_ids"]
        ] + [
            GraphEdge(row["id"], target, "failure")
            for row in self.payload["nodes"]
            for target in row["failure_ids"]
        ]
        width = max([node.x for node in nodes], default=0) + 220
        height = max([node.y for node in nodes], default=0) + 120
        return {
            "nodes": [asdict(node) for node in nodes],
            "edges": [asdict(edge) for edge in edges],
            "width": max(640, width),
            "height": max(360, height),
            "lanes": max(levels.values(), default=-1) + 1,
        }

    def add_node(self, node_id: str, kind: str, *, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
        normalized_id = str(node_id).strip()
        normalized_kind = str(kind).strip()
        if not normalized_id or len(normalized_id) > 128:
            raise ValueError("Node ID is invalid")
        if not normalized_kind or len(normalized_kind) > 128:
            raise ValueError("Node kind is invalid")
        if len(self.payload["nodes"]) >= self.MAX_NODES:
            raise ValueError("Workflow graph reached the node budget")
        if any(row["id"] == normalized_id for row in self.payload["nodes"]):
            raise ValueError(f"Workflow node already exists: {normalized_id}")
        self.payload["nodes"].append({
            "id": normalized_id,
            "kind": normalized_kind,
            "config": dict(config or {}),
            "next_ids": [],
            "failure_ids": [],
        })
        self._validate()
        return self.snapshot()

    def remove_node(self, node_id: str) -> dict[str, Any]:
        target = str(node_id).strip()
        if not any(row["id"] == target for row in self.payload["nodes"]):
            raise KeyError(f"Workflow node not found: {target}")
        if len(self.payload["nodes"]) <= 1:
            raise ValueError("Workflow graph cannot be empty")
        self.payload["nodes"] = [row for row in self.payload["nodes"] if row["id"] != target]
        for row in self.payload["nodes"]:
            row["next_ids"] = [item for item in row["next_ids"] if item != target]
            row["failure_ids"] = [item for item in row["failure_ids"] if item != target]
        self._validate()
        return self.snapshot()

    def connect(self, source: str, target: str, *, edge_type: str = "normal") -> dict[str, Any]:
        source_id = str(source).strip()
        target_id = str(target).strip()
        if source_id == target_id:
            raise ValueError("Workflow nodes cannot connect to themselves")
        rows = {row["id"]: row for row in self.payload["nodes"]}
        if source_id not in rows or target_id not in rows:
            raise KeyError("Workflow graph connection references an unknown node")
        key = "failure_ids" if str(edge_type).casefold() == "failure" else "next_ids"
        if target_id not in rows[source_id][key]:
            rows[source_id][key].append(target_id)
        try:
            self._validate()
        except ValueError:
            rows[source_id][key].remove(target_id)
            raise
        return self.snapshot()

    def disconnect(self, source: str, target: str, *, edge_type: str = "normal") -> dict[str, Any]:
        rows = {row["id"]: row for row in self.payload["nodes"]}
        if source not in rows:
            raise KeyError(f"Workflow node not found: {source}")
        key = "failure_ids" if str(edge_type).casefold() == "failure" else "next_ids"
        rows[source][key] = [item for item in rows[source][key] if item != target]
        self._validate()
        return self.snapshot()

    def update_node(self, node_id: str, *, kind: str | None = None, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
        row = next((item for item in self.payload["nodes"] if item["id"] == node_id), None)
        if row is None:
            raise KeyError(f"Workflow node not found: {node_id}")
        if kind is not None:
            normalized = str(kind).strip()
            if not normalized:
                raise ValueError("Node kind is empty")
            row["kind"] = normalized[:128]
        if config is not None:
            row["config"] = dict(list(dict(config).items())[:256])
        self._validate()
        return self.snapshot()

    def _topological_levels(self, *, raise_on_cycle: bool) -> dict[str, int]:
        rows = {row["id"]: row for row in self.payload["nodes"]}
        incoming: dict[str, set[str]] = {node_id: set() for node_id in rows}
        outgoing: dict[str, list[str]] = {node_id: [] for node_id in rows}
        for node_id, row in rows.items():
            for target in [*row["next_ids"], *row["failure_ids"]]:
                incoming[target].add(node_id)
                outgoing[node_id].append(target)
        queue = [node_id for node_id, parents in incoming.items() if not parents]
        levels = {node_id: 0 for node_id in queue}
        visited = 0
        while queue:
            current = queue.pop(0)
            visited += 1
            for target in outgoing[current]:
                levels[target] = max(levels.get(target, 0), levels.get(current, 0) + 1)
                incoming[target].discard(current)
                if not incoming[target]:
                    queue.append(target)
        if visited != len(rows):
            if raise_on_cycle:
                raise ValueError("Workflow graph contains a cycle")
            for node_id in rows:
                levels.setdefault(node_id, 0)
        return levels
