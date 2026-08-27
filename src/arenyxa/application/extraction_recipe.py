"""Local extraction recipe model and compiler for bounded browser extraction workflows."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from arenyxa.application.extraction_studio import ExtractionField


_ALLOWED_STEP_KINDS = frozenset({
    "navigate",
    "wait",
    "click",
    "input",
    "select",
    "hover",
    "press",
    "check",
    "uncheck",
    "double_click",
    "focus",
    "scroll",
    "loop",
    "paginate",
    "infinite_scroll",
    "extract",
    "condition",
})
_ALLOWED_PAGINATION_MODES = frozenset({"next_button", "page_parameter", "cursor", "infinite_scroll"})


@dataclass(slots=True)
class ExtractionInteractionStep:
    """One normalized browser interaction in an extraction recipe."""
    id: str
    kind: str
    selector: str = ""
    value: str = ""
    timeout_ms: int = 10000
    optional: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def normalized(self) -> "ExtractionInteractionStep":
        step_id = str(self.id).strip()
        kind = str(self.kind).strip().casefold()
        selector = str(self.selector).strip()
        value = str(self.value)
        if not step_id or len(step_id) > 128:
            raise ValueError("Extraction interaction step id is invalid")
        if kind not in _ALLOWED_STEP_KINDS:
            raise ValueError(f"Unsupported extraction interaction kind: {kind}")
        if len(selector) > 8192 or len(value) > 65536:
            raise ValueError("Extraction interaction value is oversized")
        timeout_ms = max(250, min(int(self.timeout_ms), 120000))
        metadata = dict(list(dict(self.metadata or {}).items())[:64])
        return ExtractionInteractionStep(step_id, kind, selector, value, timeout_ms, bool(self.optional), metadata)


@dataclass(slots=True)
class ExtractionLoopSpec:
    """Bounded repeated-item selector configuration."""
    selector: str
    item_limit: int = 1000
    deduplicate_by: str = ""

    def normalized(self) -> "ExtractionLoopSpec":
        selector = str(self.selector).strip()
        if not selector or len(selector) > 8192:
            raise ValueError("Loop selector is required")
        return ExtractionLoopSpec(selector, max(1, min(int(self.item_limit), 100000)), str(self.deduplicate_by).strip()[:128])


@dataclass(slots=True)
class ExtractionPaginationSpec:
    """Bounded pagination or infinite-scroll configuration."""
    mode: str
    selector: str = ""
    parameter: str = ""
    cursor_selector: str = ""
    cursor_attribute: str = ""
    start: int = 1
    step: int = 1
    maximum_pages: int = 100
    stop_when_unchanged: bool = True

    def normalized(self) -> "ExtractionPaginationSpec":
        mode = str(self.mode).strip().casefold()
        if mode not in _ALLOWED_PAGINATION_MODES:
            raise ValueError(f"Unsupported pagination mode: {mode}")
        selector = str(self.selector).strip()
        parameter = str(self.parameter).strip()
        cursor_selector = str(self.cursor_selector).strip()
        cursor_attribute = str(self.cursor_attribute).strip()
        if mode == "next_button" and not selector:
            raise ValueError("Next-button pagination requires a selector")
        if mode in {"page_parameter", "cursor"} and not parameter:
            raise ValueError("Parameterized pagination requires a parameter name")
        if mode == "cursor" and not cursor_selector:
            raise ValueError("Cursor pagination requires a cursor selector")
        return ExtractionPaginationSpec(
            mode=mode,
            selector=selector[:8192],
            parameter=parameter[:256],
            cursor_selector=cursor_selector[:8192],
            cursor_attribute=cursor_attribute[:256],
            start=max(-1_000_000, min(int(self.start), 1_000_000)),
            step=max(-10000, min(int(self.step), 10000)) or 1,
            maximum_pages=max(1, min(int(self.maximum_pages), 10000)),
            stop_when_unchanged=bool(self.stop_when_unchanged),
        )


@dataclass(slots=True)
class ExtractionRecipe:
    """Serializable local extraction plan with fields, interactions, loop, and pagination."""
    name: str
    source_url: str
    fields: list[ExtractionField]
    steps: list[ExtractionInteractionStep] = field(default_factory=list)
    loop: ExtractionLoopSpec | None = None
    pagination: ExtractionPaginationSpec | None = None
    authentication_required: bool = False
    max_records: int = 10000

    def normalized(self) -> "ExtractionRecipe":
        name = str(self.name).strip()
        url = str(self.source_url).strip()
        if not name or len(name) > 160:
            raise ValueError("Extraction recipe name is invalid")
        if not url or len(url) > 8192:
            raise ValueError("Extraction recipe source URL is invalid")
        fields = [item.normalized() for item in list(self.fields)[:256]]
        if not fields:
            raise ValueError("Extraction recipe requires at least one field")
        steps = [item.normalized() for item in list(self.steps)[:256]]
        ids = [item.id for item in steps]
        if len(ids) != len(set(ids)):
            raise ValueError("Extraction interaction step ids must be unique")
        return ExtractionRecipe(
            name=name,
            source_url=url,
            fields=fields,
            steps=steps,
            loop=None if self.loop is None else self.loop.normalized(),
            pagination=None if self.pagination is None else self.pagination.normalized(),
            authentication_required=bool(self.authentication_required),
            max_records=max(1, min(int(self.max_records), 1_000_000)),
        )

    def snapshot(self) -> dict[str, Any]:
        normalized = self.normalized()
        return {
            "schema": "arenyxa.extraction-recipe/v1",
            "name": normalized.name,
            "source_url": normalized.source_url,
            "fields": [asdict(item) for item in normalized.fields],
            "steps": [asdict(item) for item in normalized.steps],
            "loop": None if normalized.loop is None else asdict(normalized.loop),
            "pagination": None if normalized.pagination is None else asdict(normalized.pagination),
            "authentication_required": normalized.authentication_required,
            "max_records": normalized.max_records,
        }


class ExtractionRecipeCompiler:
    """Validate and compile extraction recipes into explicit runtime-aware flow drafts."""
    MAX_NODES = 1024

    def compile(self, recipe: ExtractionRecipe) -> dict[str, Any]:
        item = recipe.normalized()
        nodes: list[dict[str, Any]] = [
            {"id": "navigate", "kind": "browser", "config": {"url": item.source_url, "wait": "domcontentloaded"}},
        ]
        for step in item.steps:
            config = {
                "action": step.kind,
                "selector": step.selector,
                "value": step.value,
                "timeout_ms": step.timeout_ms,
                "optional": step.optional,
                "metadata": step.metadata,
            }
            nodes.append({"id": f"interaction_{step.id}", "kind": "browser_action", "config": config})
        if item.loop is not None:
            nodes.append({
                "id": "collection_loop",
                "kind": "loop",
                "config": {
                    "selector": item.loop.selector,
                    "item_limit": item.loop.item_limit,
                    "deduplicate_by": item.loop.deduplicate_by,
                },
            })
        nodes.append({
            "id": "extract",
            "kind": "extract",
            "config": {"fields": [asdict(field) for field in item.fields], "max_records": item.max_records},
        })
        if item.pagination is not None:
            nodes.append({"id": "paginate", "kind": "paginate", "config": asdict(item.pagination)})
        nodes.extend([
            {"id": "normalize", "kind": "transform", "config": {"operation": "normalize"}},
            {"id": "validate", "kind": "validate", "config": {"required": [field.name for field in item.fields if field.required]}},
            {"id": "sink", "kind": "sink", "config": {"target": "dataset_revision"}},
        ])
        if len(nodes) > self.MAX_NODES:
            raise ValueError("Extraction recipe compiled beyond the node budget")
        for current, following in zip(nodes, nodes[1:]):
            current["next_ids"] = [following["id"]]
        nodes[-1]["next_ids"] = []
        return {
            "schema": "arenyxa.workflow/v1",
            "name": item.name,
            "metadata": {
                "generated_by": "Arenyxa Extraction Lab",
                "runtime": "arenyxa.extraction_recipe",
                "flow_role": "runtime-draft",
                "direct_executor": "ExtractionRecipeExecutor",
                "authentication_required": item.authentication_required,
                "max_records": item.max_records,
            },
            "nodes": nodes,
        }

    def validate(self, recipe: ExtractionRecipe) -> list[str]:
        item = recipe.normalized()
        warnings: list[str] = []
        if item.authentication_required and not any(step.kind in {"input", "click"} for step in item.steps):
            warnings.append("Authentication is enabled but the recipe has no input/click interaction steps")
        if item.pagination is not None and item.pagination.maximum_pages > 1000:
            warnings.append("Pagination exceeds 1,000 pages; verify rate limits and target authorization")
        if item.loop is None and any(field.multiple for field in item.fields):
            warnings.append("Multiple-value fields are configured without an explicit collection loop")
        if item.max_records > 100000:
            warnings.append("Record budget exceeds 100,000; use server-side storage and bounded execution")
        return warnings

    @staticmethod
    def from_mapping(payload: dict[str, Any]) -> ExtractionRecipe:
        fields = [ExtractionField(**dict(row)) for row in list(payload.get("fields") or []) if isinstance(row, dict)]
        steps = [ExtractionInteractionStep(**dict(row)) for row in list(payload.get("steps") or []) if isinstance(row, dict)]
        loop_payload = payload.get("loop")
        pagination_payload = payload.get("pagination")
        return ExtractionRecipe(
            name=str(payload.get("name") or "Extraction Recipe"),
            source_url=str(payload.get("source_url") or ""),
            fields=fields,
            steps=steps,
            loop=ExtractionLoopSpec(**dict(loop_payload)) if isinstance(loop_payload, dict) else None,
            pagination=ExtractionPaginationSpec(**dict(pagination_payload)) if isinstance(pagination_payload, dict) else None,
            authentication_required=bool(payload.get("authentication_required")),
            max_records=int(payload.get("max_records") or 10000),
        )
