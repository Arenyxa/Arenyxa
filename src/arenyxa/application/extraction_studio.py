from __future__ import annotations

from dataclasses import field
import json
import re
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from arenyxa.compat import dataclass
from arenyxa.domain.models import NetworkEvent
from arenyxa.infrastructure.capture.professional import ExtractionPlan, NoCodeExtractionPlanner


_SELECTOR_TYPES = frozenset({"css", "xpath", "jsonpath", "text", "aria", "attribute"})


@dataclass(slots=True)
class ExtractionField:
    name: str
    selector_type: str
    selector: str
    attribute: str = ""
    required: bool = False
    multiple: bool = False

    def normalized(self) -> "ExtractionField":
        name = str(self.name).strip()
        selector_type = str(self.selector_type).strip().casefold()
        selector = str(self.selector).strip()
        attribute = str(self.attribute).strip()
        if not name or len(name) > 128:
            raise ValueError("Extraction field name is invalid")
        if selector_type not in _SELECTOR_TYPES:
            raise ValueError(f"Unsupported selector type: {selector_type}")
        if not selector or len(selector) > 8192:
            raise ValueError("Extraction selector is empty or oversized")
        if len(attribute) > 256:
            raise ValueError("Extraction attribute is oversized")
        return ExtractionField(name, selector_type, selector, attribute, bool(self.required), bool(self.multiple))


@dataclass(slots=True)
class ExtractionStudioResult:
    source_url: str
    recommended_mode: str
    fields: list[ExtractionField]
    discovered_sources: list[dict[str, Any]]
    pagination: list[dict[str, str]]
    interactions: list[str]
    workflow_draft: dict[str, Any]
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExtractionPreviewResult:
    body_ref: str
    content_type: str
    records: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)


class ExtractionDryRun:
    MAX_BODIES = 24
    MAX_BODY_BYTES = 2 * 1024 * 1024
    MAX_VALUES_PER_FIELD = 100

    def preview(
        self,
        events: Sequence[NetworkEvent],
        fields: Sequence[ExtractionField],
        resolve_body: Callable[[str, int], bytes | None],
    ) -> ExtractionPreviewResult:
        normalized = [item.normalized() for item in list(fields)[:256]]
        refs: list[tuple[str, str]] = []
        for event in events:
            ref = str(event.response_body_ref or "").strip()
            if not ref or any(existing == ref for existing, _ in refs):
                continue
            ctype = str(event.response_headers.get("content-type", ""))
            refs.append((ref, ctype))
            if len(refs) >= self.MAX_BODIES:
                break
        if not refs:
            return ExtractionPreviewResult("", "", [], ["No captured response body is available for local dry run"] )
        warnings: list[str] = []
        for body_ref, content_type in refs:
            payload = resolve_body(body_ref, self.MAX_BODY_BYTES)
            if not payload:
                continue
            try:
                records = self._extract(payload, content_type, normalized)
            except (UnicodeError, ValueError, TypeError) as exc:
                warnings.append(f"{body_ref}: {type(exc).__name__}: {exc}")
                continue
            if records:
                return ExtractionPreviewResult(body_ref, content_type, records[: self.MAX_VALUES_PER_FIELD], warnings)
        warnings.append("Captured bodies were inspected, but none produced field values")
        return ExtractionPreviewResult(refs[0][0], refs[0][1], [], warnings)

    def _extract(self, payload: bytes, content_type: str, fields: Sequence[ExtractionField]) -> list[dict[str, Any]]:
        lowered = content_type.casefold()
        if "json" in lowered or payload.lstrip()[:1] in {b"{", b"["}:
            data = json.loads(payload.decode("utf-8", errors="strict"))
            record: dict[str, Any] = {}
            for field in fields:
                if field.selector_type != "jsonpath":
                    continue
                values = self._jsonpath(data, field.selector)
                if values:
                    record[field.name] = values if field.multiple else values[0]
                elif field.required:
                    record[field.name] = None
            return [record] if record else []
        try:
            from lxml import html
        except ImportError as exc:
            raise ValueError("lxml is required for HTML dry run") from exc
        tree = html.fromstring(payload.decode("utf-8", errors="replace"))
        output: dict[str, Any] = {}
        for field in fields:
            values: list[Any] = []
            if field.selector_type == "xpath":
                raw_values = tree.xpath(field.selector)
                values = [self._node_value(item, field.attribute) for item in raw_values[: self.MAX_VALUES_PER_FIELD]]
            elif field.selector_type == "css":
                raw_values = self._css_nodes(tree, field.selector)
                values = [self._node_value(item, field.attribute) for item in raw_values[: self.MAX_VALUES_PER_FIELD]]
            elif field.selector_type == "text":
                needle = field.selector.casefold()
                raw_values = tree.xpath("//*[contains(translate(normalize-space(string(.)), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), $needle)]", needle=needle)
                values = [self._node_value(item, field.attribute) for item in raw_values[: self.MAX_VALUES_PER_FIELD]]
            elif field.selector_type == "attribute":
                selector, _, attribute = field.selector.partition("@")
                attribute = field.attribute or attribute
                raw_values = self._css_nodes(tree, selector.strip()) if selector.strip() else []
                values = [self._node_value(item, attribute) for item in raw_values[: self.MAX_VALUES_PER_FIELD]]
            elif field.selector_type == "aria":
                escaped = field.selector.replace('"', '\"')
                raw_values = self._css_nodes(tree, f'[aria-label="{escaped}"]')
                values = [self._node_value(item, field.attribute) for item in raw_values[: self.MAX_VALUES_PER_FIELD]]
            values = [item for item in values if item not in (None, "")]
            if values:
                output[field.name] = values if field.multiple else values[0]
            elif field.required:
                output[field.name] = None
        return [output] if output else []

    @staticmethod
    def _css_nodes(tree: Any, selector: str) -> list[Any]:
        try:
            return list(tree.cssselect(selector))
        except ImportError:
            text = selector.strip()
            if not text or any(token in text for token in (",", ">", "+", "~", ":")):
                raise ValueError("cssselect package is required for advanced CSS selectors")
            attribute_match = re.fullmatch(r"(?:([A-Za-z][\w-]*))?\[([A-Za-z_:][\w:.-]*)(?:=[\"']?([^\]\"']+)[\"']?)?\]", text)
            if attribute_match:
                tag, attribute, value = attribute_match.groups()
                tag = tag or "*"
                if value is None:
                    return list(tree.xpath(f"//{tag}[@{attribute}]"))
                return list(tree.xpath(f"//{tag}[@{attribute}=$value]", value=value))
            if text.startswith("#") and re.fullmatch(r"#[A-Za-z_][\w-]*", text):
                return list(tree.xpath("//*[@id=$value]", value=text[1:]))
            if text.startswith(".") and re.fullmatch(r"\.[A-Za-z_][\w-]*", text):
                class_name = text[1:]
                return list(tree.xpath("//*[contains(concat(' ', normalize-space(@class), ' '), $value)]", value=f" {class_name} "))
            if re.fullmatch(r"[A-Za-z][\w-]*", text):
                return list(tree.xpath(f"//{text}"))
            raise ValueError("cssselect package is required for advanced CSS selectors")

    @staticmethod
    def _node_value(node: Any, attribute: str) -> Any:
        if isinstance(node, (str, int, float, bool)):
            return node
        if attribute and hasattr(node, "get"):
            return node.get(attribute)
        if hasattr(node, "text_content"):
            return str(node.text_content()).strip()
        return str(node).strip()

    @staticmethod
    def _jsonpath(data: Any, expression: str) -> list[Any]:
        text = str(expression).strip()
        if not text.startswith("$"):
            raise ValueError("JSONPath dry run requires a path beginning with $")
        if text == "$":
            return [data]
        tokens = re.findall(r"\.([A-Za-z0-9_-]+)|\[([0-9]+|\*)\]", text[1:])
        if not tokens:
            raise ValueError("Unsupported JSONPath expression")
        current = [data]
        for key, index in tokens:
            following: list[Any] = []
            for item in current:
                if key:
                    if isinstance(item, dict) and key in item:
                        following.append(item[key])
                elif index == "*":
                    if isinstance(item, list):
                        following.extend(item[: ExtractionDryRun.MAX_VALUES_PER_FIELD])
                elif isinstance(item, list):
                    position = int(index)
                    if 0 <= position < len(item):
                        following.append(item[position])
            current = following[: ExtractionDryRun.MAX_VALUES_PER_FIELD]
            if not current:
                break
        return current


class ExtractionStudioService:
    MAX_EVENTS = 20_000
    MAX_FIELDS = 256

    def __init__(self) -> None:
        self.planner = NoCodeExtractionPlanner()

    def analyze(
        self,
        events: Sequence[NetworkEvent],
        *,
        source_url: str = "",
        fields: Sequence[ExtractionField] = (),
    ) -> ExtractionStudioResult:
        selected_events = list(events[: self.MAX_EVENTS])
        normalized_fields = [item.normalized() for item in list(fields)[: self.MAX_FIELDS]]
        plan = self.planner.build(selected_events, source_url)
        warnings: list[str] = []
        if len(events) > self.MAX_EVENTS:
            warnings.append(f"Only the first {self.MAX_EVENTS:,} events were analyzed")
        if len(fields) > self.MAX_FIELDS:
            warnings.append(f"Only the first {self.MAX_FIELDS:,} extraction fields were compiled")
        target = self._source_url(source_url, plan)
        if not target:
            warnings.append("No source URL was available; select a captured request or enter a source URL")
        return ExtractionStudioResult(
            source_url=target,
            recommended_mode=plan.recommended_mode,
            fields=normalized_fields,
            discovered_sources=list(plan.structured_sources),
            pagination=list(plan.pagination),
            interactions=list(plan.interactions),
            workflow_draft=self._compile_workflow(plan, target, normalized_fields),
            warnings=warnings,
        )

    @staticmethod
    def _source_url(source_url: str, plan: ExtractionPlan) -> str:
        candidate = str(source_url).strip()
        if not candidate and plan.structured_sources:
            candidate = str(plan.structured_sources[0].get("url") or "").strip()
        if not candidate:
            return ""
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Extraction source URL must use HTTP or HTTPS")
        return candidate

    @staticmethod
    def _compile_workflow(plan: ExtractionPlan, source_url: str, fields: Sequence[ExtractionField]) -> dict[str, Any]:
        nodes: list[dict[str, Any]] = []
        if plan.recommended_mode == "api" and plan.structured_sources:
            source = plan.structured_sources[0]
            nodes.append({
                "id": "source",
                "kind": "http",
                "config": {
                    "method": str(source.get("method") or "GET"),
                    "url": str(source.get("url") or source_url),
                    "response": "structured",
                },
            })
        else:
            nodes.append({
                "id": "source",
                "kind": "browser",
                "config": {"url": source_url, "wait": "domcontentloaded"},
            })
        nodes.append({
            "id": "extract",
            "kind": "extract",
            "config": {
                "fields": [
                    {
                        "name": item.name,
                        "type": item.selector_type,
                        "selector": item.selector,
                        "attribute": item.attribute,
                        "required": item.required,
                        "multiple": item.multiple,
                    }
                    for item in fields
                ]
            },
        })
        for index, pagination in enumerate(plan.pagination[:16], start=1):
            nodes.append({
                "id": f"paginate_{index}",
                "kind": "paginate",
                "config": dict(pagination),
            })
        for index, interaction in enumerate(plan.interactions[:16], start=1):
            nodes.append({
                "id": f"interaction_{index}",
                "kind": "browser_action",
                "config": {"action": interaction},
            })
        nodes.extend([
            {"id": "normalize", "kind": "transform", "config": {"operation": "normalize"}},
            {"id": "validate", "kind": "validate", "config": {"required": [item.name for item in fields if item.required]}},
            {"id": "sink", "kind": "sink", "config": {"target": "dataset_revision"}},
        ])
        for current, following in zip(nodes, nodes[1:]):
            current["next_ids"] = [following["id"]]
        nodes[-1]["next_ids"] = []
        return {
            "schema": "arenyxa.extraction-workflow/v1",
            "name": "Professional Web Extraction",
            "source_url": source_url,
            "recommended_mode": plan.recommended_mode,
            "nodes": nodes,
        }

@dataclass(slots=True)
class ExtractionPickResult:
    url: str
    tag: str
    text: str
    attributes: dict[str, str]
    primary_selector: str
    candidates: list[dict[str, Any]]
    suggested_field: ExtractionField
    collection_selector: str = ""
    collection_match_count: int = 0
    collection_confidence: float = 0.0


class ExtractionLivePicker:
    MAX_TIMEOUT_SECONDS = 300

    def pick(self, url: str, *, timeout_seconds: int = 120, headless: bool = False) -> ExtractionPickResult:
        parsed = urlsplit(str(url).strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Extraction picker requires a valid http/https URL")
        seconds = max(10, min(self.MAX_TIMEOUT_SECONDS, int(timeout_seconds)))
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError(
                "Extraction point-and-click requires Playwright Chromium: install the browser optional dependency first"
            ) from exc
        from arenyxa.application.nextgen import SelectorStudio

        selected: dict[str, Any] = {}
        selected_event = __import__("threading").Event()

        def receive(_source: Any, payload: Any) -> None:
            if not isinstance(payload, dict) or selected_event.is_set():
                return
            selected.update({
                "tag": str(payload.get("tag", ""))[:80],
                "text": str(payload.get("text", ""))[:1000],
                "selector": str(payload.get("selector", ""))[:8192],
                "attributes": {
                    str(key)[:128]: str(value)[:1000]
                    for key, value in dict(payload.get("attributes") or {}).items()
                    if value is not None
                },
            })
            selected_event.set()

        picker_script = r"""
        (() => {
          if (window.__arenyxaExtractionPickerInstalled) return;
          window.__arenyxaExtractionPickerInstalled = true;
          const esc = v => (window.CSS && CSS.escape ? CSS.escape(String(v)) : String(v).replace(/[^a-zA-Z0-9_-]/g, '\\$&'));
          const stable = ['data-testid','data-test','data-qa','aria-label','name','itemprop'];
          const locator = el => {
            if (!el || !el.tagName) return '';
            const tag = el.tagName.toLowerCase();
            if (el.id && !/[0-9a-f]{12,}|\d{5,}/i.test(el.id)) return '#' + esc(el.id);
            for (const key of stable) {
              const value = el.getAttribute(key);
              if (value && value.length < 180) return `${tag}[${key}=${JSON.stringify(value)}]`;
            }
            const classes = [...el.classList].filter(v => v.length < 64 && !/[0-9a-f]{8,}|^(css|sc|jsx|chakra|mui|ant)[-_]/i.test(v)).slice(0, 3);
            if (classes.length) return tag + classes.map(v => '.' + esc(v)).join('');
            let index = 1, sib = el;
            while ((sib = sib.previousElementSibling)) if (sib.tagName === el.tagName) index++;
            const parent = el.parentElement;
            if (parent && parent.tagName) {
              const ptag = parent.tagName.toLowerCase();
              return `${ptag} > ${tag}:nth-of-type(${index})`;
            }
            return `${tag}:nth-of-type(${index})`;
          };
          const overlay = document.createElement('div');
          Object.assign(overlay.style, {
            position:'fixed', pointerEvents:'none', zIndex:'2147483646', border:'2px solid #7c5cff',
            background:'rgba(124,92,255,.10)', borderRadius:'6px', display:'none', boxSizing:'border-box'
          });
          const hint = document.createElement('div');
          hint.textContent = 'Arenyxa Extraction Picker · click an element · Esc cancels';
          Object.assign(hint.style, {
            position:'fixed', left:'16px', bottom:'16px', zIndex:'2147483647', padding:'9px 12px',
            borderRadius:'10px', background:'rgba(18,18,22,.92)', color:'#fff', font:'13px system-ui,sans-serif',
            boxShadow:'0 8px 32px rgba(0,0,0,.28)'
          });
          document.documentElement.appendChild(overlay);
          document.documentElement.appendChild(hint);
          const move = e => {
            const el = e.target;
            if (!el || el === overlay || el === hint || !el.getBoundingClientRect) return;
            const r = el.getBoundingClientRect();
            Object.assign(overlay.style, {display:'block', left:r.left+'px', top:r.top+'px', width:r.width+'px', height:r.height+'px'});
          };
          const click = e => {
            const el = e.target;
            if (!el || el === overlay || el === hint || !el.tagName) return;
            e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
            const attrs = {};
            for (const a of [...el.attributes].slice(0, 64)) attrs[a.name] = a.value;
            try { window.arenyxaExtractionPick({tag:el.tagName.toLowerCase(), text:(el.innerText || el.textContent || '').trim(), selector:locator(el), attributes:attrs}); } catch (_) {}
          };
          const key = e => { if (e.key === 'Escape') { try { window.arenyxaExtractionPick({tag:'', text:'', selector:'', attributes:{}}); } catch (_) {} } };
          document.addEventListener('mousemove', move, true);
          document.addEventListener('click', click, true);
          document.addEventListener('keydown', key, true);
        })();
        """

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=headless)
            context = browser.new_context()
            page = context.new_page()
            try:
                page.expose_binding("arenyxaExtractionPick", receive)
                page.add_init_script(picker_script)
                page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                page.evaluate(picker_script)
                deadline = __import__("time").monotonic() + seconds
                while not selected_event.is_set() and __import__("time").monotonic() < deadline:
                    page.wait_for_timeout(100)
                if not selected_event.is_set():
                    raise TimeoutError("Extraction picker timed out before an element was selected")
                selector = str(selected.get("selector") or "")
                if not selector:
                    raise RuntimeError("Extraction picker was cancelled")
                markup = page.content()
                analysis = SelectorStudio().analyze(markup, selector, "css")
            finally:
                context.close()
                browser.close()

        candidates = list(analysis.get("candidates") or [])[:12]
        primary = candidates[0] if candidates else {"selector_type": "css", "selector": selector, "match_count": 1, "score": 0.5}
        collection_candidates = [
            item for item in candidates
            if 2 <= int(item.get("match_count") or 0) <= 500 and float(item.get("score") or 0.0) >= 0.35
        ]
        collection = max(
            collection_candidates,
            key=lambda item: (float(item.get("score") or 0.0), -int(item.get("match_count") or 0)),
            default=None,
        )
        selected_candidate = collection or primary
        text = str(selected.get("text") or "")
        attrs = dict(selected.get("attributes") or {})
        field_name = self._field_name(selected.get("tag", "field"), attrs, text)
        attribute = ""
        if str(selected.get("tag")) in {"img", "source"} and attrs.get("src"):
            attribute = "src"
        elif str(selected.get("tag")) == "a" and attrs.get("href"):
            attribute = "href"
        suggested = ExtractionField(
            name=field_name,
            selector_type=str(selected_candidate.get("selector_type") or "css"),
            selector=str(selected_candidate.get("selector") or selector),
            attribute=attribute,
            required=False,
            multiple=collection is not None,
        ).normalized()
        return ExtractionPickResult(
            url=str(url),
            tag=str(selected.get("tag") or ""),
            text=text,
            attributes=attrs,
            primary_selector=str(primary.get("selector") or selector),
            candidates=candidates,
            suggested_field=suggested,
            collection_selector="" if collection is None else str(collection.get("selector") or ""),
            collection_match_count=0 if collection is None else int(collection.get("match_count") or 0),
            collection_confidence=0.0 if collection is None else float(collection.get("score") or 0.0),
        )

    @staticmethod
    def _field_name(tag: Any, attributes: dict[str, str], text: str) -> str:
        for key in ("data-testid", "data-test", "data-qa", "name", "itemprop", "aria-label", "id"):
            value = str(attributes.get(key) or "").strip()
            if value:
                candidate = re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_").casefold()
                if candidate:
                    return candidate[:96]
        if text:
            candidate = re.sub(r"[^A-Za-z0-9_]+", "_", text[:48]).strip("_").casefold()
            if candidate:
                return candidate[:96]
        candidate = re.sub(r"[^A-Za-z0-9_]+", "_", str(tag)).strip("_").casefold()
        return candidate[:96] or "field"
