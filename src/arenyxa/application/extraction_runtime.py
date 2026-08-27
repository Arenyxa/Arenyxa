from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from arenyxa.application.extraction_recipe import ExtractionInteractionStep, ExtractionRecipe
from arenyxa.application.extraction_studio import ExtractionField
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard


@dataclass(slots=True)
class ExtractionExecutionResult:
    source_url: str
    final_url: str
    pages_visited: int
    records: list[dict[str, Any]]
    interactions_executed: int
    duplicates_removed: int
    duration_seconds: float
    warnings: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class ExtractionRecipeExecutor:
    MAX_PAGES = 10000
    MAX_RECORDS = 1_000_000
    MAX_INTERACTIONS = 256
    MAX_FIELD_VALUES = 10000

    def __init__(self, *, network_policy: NetworkGuardPolicy | None = None) -> None:
        self.guard = NetworkUseGuard(network_policy or NetworkGuardPolicy())
        self._playwright_error: type[BaseException] = RuntimeError

    def execute(
        self,
        recipe: ExtractionRecipe,
        *,
        headless: bool = True,
        browser_timeout_seconds: int = 60,
        secret_resolver: Callable[[str], str | None] | None = None,
        progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> ExtractionExecutionResult:
        item = recipe.normalized()
        parsed = urlsplit(item.source_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Extraction recipe requires an http/https source URL")
        self.guard.check_target(parsed.hostname, resolve_dns=True)
        timeout_ms = max(5000, min(int(browser_timeout_seconds) * 1000, 120000))
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("Extraction execution requires Playwright Chromium") from exc
        self._playwright_error = PlaywrightError
        started = time.monotonic()
        records: list[dict[str, Any]] = []
        warnings: list[str] = []
        seen: set[str] = set()
        pages_visited = 0
        interactions = 0
        duplicates = 0
        final_url = item.source_url
        max_pages = min(item.pagination.maximum_pages if item.pagination is not None else 1, self.MAX_PAGES)
        max_records = min(item.max_records, self.MAX_RECORDS)

        with sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=bool(headless))
            context = browser.new_context()
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            try:
                self._navigate(page, item.source_url, timeout_ms)
                self._guard_current_url(page.url)
                interactions += self._run_steps(page, item.steps, secret_resolver, progress)
                page_index = 0
                stable_scroll_rounds = 0
                previous_scroll_height = -1
                while pages_visited < max_pages and len(records) < max_records:
                    pages_visited += 1
                    page_index += 1
                    batch = self._extract_page(page, item.fields, item.loop, max_records - len(records), warnings)
                    for record in batch:
                        identity = self._record_identity(record, item.loop.deduplicate_by if item.loop is not None else "")
                        if identity in seen:
                            duplicates += 1
                            continue
                        seen.add(identity)
                        records.append(record)
                        if len(records) >= max_records:
                            break
                    self._emit(progress, {
                        "stage": "page",
                        "page": page_index,
                        "records": len(records),
                        "url": page.url,
                    })
                    pagination = item.pagination
                    if pagination is None or len(records) >= max_records:
                        break
                    if pagination.mode == "next_button":
                        locator = page.locator(pagination.selector).first
                        if locator.count() == 0:
                            break
                        try:
                            disabled = locator.get_attribute("disabled") is not None or locator.get_attribute("aria-disabled") == "true"
                        except PlaywrightError:
                            disabled = False
                        if disabled:
                            break
                        before = page.url
                        try:
                            locator.click(timeout=timeout_ms)
                            page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
                        except PlaywrightTimeoutError:
                            warnings.append("Next-page navigation exceeded the configured timeout")
                        self._guard_current_url(page.url)
                        if page.url == before:
                            page.wait_for_timeout(250)
                    elif pagination.mode == "page_parameter":
                        next_url = self._page_parameter_url(item.source_url, pagination.parameter, pagination.start + page_index * pagination.step)
                        self._navigate(page, next_url, timeout_ms)
                        self._guard_current_url(page.url)
                    elif pagination.mode == "cursor":
                        cursor_locator = page.locator(pagination.cursor_selector).first
                        if cursor_locator.count() == 0:
                            break
                        cursor_value = (
                            cursor_locator.get_attribute(pagination.cursor_attribute)
                            if pagination.cursor_attribute
                            else cursor_locator.inner_text()
                        )
                        cursor_value = str(cursor_value or "").strip()
                        if not cursor_value:
                            break
                        next_url = self._string_parameter_url(page.url or item.source_url, pagination.parameter, cursor_value)
                        self._navigate(page, next_url, timeout_ms)
                        self._guard_current_url(page.url)
                    elif pagination.mode == "infinite_scroll":
                        try:
                            height = int(page.evaluate("() => Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)"))
                            page.evaluate("() => window.scrollTo(0, Math.max(document.body.scrollHeight, document.documentElement.scrollHeight))")
                            page.wait_for_timeout(600)
                            new_height = int(page.evaluate("() => Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)"))
                        except (PlaywrightError, ValueError, TypeError) as exc:
                            warnings.append(f"Infinite-scroll probe failed: {type(exc).__name__}")
                            break
                        if new_height <= height or new_height == previous_scroll_height:
                            stable_scroll_rounds += 1
                        else:
                            stable_scroll_rounds = 0
                        previous_scroll_height = new_height
                        if stable_scroll_rounds >= 2:
                            break
                    else:
                        break
            finally:
                try:
                    final_url = str(page.url or item.source_url)
                except self._playwright_error:
                    final_url = item.source_url
                context.close()
                browser.close()
        return ExtractionExecutionResult(
            source_url=item.source_url,
            final_url=final_url,
            pages_visited=pages_visited,
            records=records,
            interactions_executed=interactions,
            duplicates_removed=duplicates,
            duration_seconds=round(max(0.0, time.monotonic() - started), 6),
            warnings=warnings,
        )

    def _run_steps(
        self,
        page: Any,
        steps: list[ExtractionInteractionStep],
        secret_resolver: Callable[[str], str | None] | None,
        progress: Callable[[dict[str, Any]], None] | None,
    ) -> int:
        executed = 0
        for step in steps[: self.MAX_INTERACTIONS]:
            try:
                value = self._resolve_value(step.value, secret_resolver)
                if step.kind == "wait":
                    if step.selector:
                        page.locator(step.selector).first.wait_for(state="visible", timeout=step.timeout_ms)
                    else:
                        page.wait_for_timeout(min(step.timeout_ms, 30000))
                elif step.kind == "click":
                    page.locator(step.selector).first.click(timeout=step.timeout_ms)
                elif step.kind == "input":
                    page.locator(step.selector).first.fill(value, timeout=step.timeout_ms)
                elif step.kind == "select":
                    page.locator(step.selector).first.select_option(value, timeout=step.timeout_ms)
                elif step.kind == "hover":
                    page.locator(step.selector).first.hover(timeout=step.timeout_ms)
                elif step.kind == "press":
                    if not value.strip():
                        raise ValueError("Press interaction requires a key value")
                    page.locator(step.selector).first.press(value, timeout=step.timeout_ms)
                elif step.kind == "check":
                    page.locator(step.selector).first.check(timeout=step.timeout_ms)
                elif step.kind == "uncheck":
                    page.locator(step.selector).first.uncheck(timeout=step.timeout_ms)
                elif step.kind == "double_click":
                    page.locator(step.selector).first.dblclick(timeout=step.timeout_ms)
                elif step.kind == "focus":
                    page.locator(step.selector).first.focus(timeout=step.timeout_ms)
                elif step.kind == "scroll":
                    if step.selector:
                        page.locator(step.selector).first.scroll_into_view_if_needed(timeout=step.timeout_ms)
                    else:
                        page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
                elif step.kind == "condition":
                    present = page.locator(step.selector).count() > 0
                    expected = value.strip().casefold() not in {"false", "0", "no", "absent"}
                    if present != expected and not step.optional:
                        raise RuntimeError(f"Condition failed for selector: {step.selector}")
                elif step.kind in {"navigate", "loop", "paginate", "extract"}:
                    continue
                else:
                    raise ValueError(f"Unsupported executable extraction step: {step.kind}")
                executed += 1
                self._emit(progress, {"stage": "interaction", "id": step.id, "kind": step.kind})
            except (RuntimeError, ValueError) as exc:
                if step.optional:
                    self._emit(progress, {"stage": "interaction-skipped", "id": step.id, "error": str(exc)[:500]})
                    continue
                raise
            except (OSError, TimeoutError, self._playwright_error) as exc:
                if step.optional:
                    self._emit(progress, {"stage": "interaction-skipped", "id": step.id, "error": type(exc).__name__})
                    continue
                raise RuntimeError(f"Extraction interaction failed: {step.id}: {type(exc).__name__}") from exc
        return executed

    def _extract_page(
        self,
        page: Any,
        fields: list[ExtractionField],
        loop: Any,
        remaining: int,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        if remaining <= 0:
            return []
        if loop is None:
            return [self._extract_record(page, fields, warnings)]
        collection = page.locator(loop.selector)
        count = min(collection.count(), loop.item_limit, remaining)
        rows: list[dict[str, Any]] = []
        for index in range(count):
            rows.append(self._extract_record(collection.nth(index), fields, warnings))
        return rows

    def _extract_record(self, scope: Any, fields: list[ExtractionField], warnings: list[str]) -> dict[str, Any]:
        record: dict[str, Any] = {}
        for field in fields:
            try:
                values = self._field_values(scope, field)
            except (OSError, RuntimeError, ValueError, self._playwright_error) as exc:
                if field.required:
                    warnings.append(f"Required field {field.name} failed: {type(exc).__name__}")
                values = []
            if field.multiple:
                record[field.name] = values[: self.MAX_FIELD_VALUES]
            else:
                record[field.name] = values[0] if values else None
        return record

    def _field_values(self, scope: Any, field: ExtractionField) -> list[Any]:
        selector_type = field.selector_type.casefold()
        if selector_type == "xpath":
            locator = scope.locator(f"xpath={field.selector}")
        elif selector_type == "text":
            locator = scope.get_by_text(field.selector)
        elif selector_type == "aria":
            locator = scope.locator(f"[aria-label={json.dumps(field.selector)}]")
        else:
            locator = scope.locator(field.selector)
        count = min(locator.count(), self.MAX_FIELD_VALUES if field.multiple else 1)
        values: list[Any] = []
        for index in range(count):
            item = locator.nth(index)
            if field.attribute:
                values.append(item.get_attribute(field.attribute))
            elif selector_type == "attribute":
                values.append(item.get_attribute("value"))
            else:
                values.append(item.inner_text())
        return values

    def _navigate(self, page: Any, url: str, timeout_ms: int) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Extraction navigation target must be http/https")
        self.guard.check_target(parsed.hostname, resolve_dns=True)
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

    def _guard_current_url(self, url: str) -> None:
        parsed = urlsplit(str(url))
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            self.guard.check_target(parsed.hostname, resolve_dns=True)

    @staticmethod
    def _page_parameter_url(url: str, parameter: str, value: int) -> str:
        return ExtractionRecipeExecutor._string_parameter_url(url, parameter, str(value))

    @staticmethod
    def _string_parameter_url(url: str, parameter: str, value: str) -> str:
        parsed = urlsplit(url)
        rows = parse_qsl(parsed.query, keep_blank_values=True)
        output = [(key, str(value) if key == parameter else item) for key, item in rows]
        if not any(key == parameter for key, _item in rows):
            output.append((parameter, str(value)))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(output), parsed.fragment))

    @staticmethod
    def _resolve_value(value: str, secret_resolver: Callable[[str], str | None] | None) -> str:
        text = str(value)
        prefix = "${secret."
        if text.startswith(prefix) and text.endswith("}") and secret_resolver is not None:
            key = text[len(prefix):-1]
            resolved = secret_resolver(key)
            if resolved is None:
                raise KeyError(f"Secret was not resolved: {key}")
            return str(resolved)
        return text

    @staticmethod
    def _record_identity(record: dict[str, Any], field: str) -> str:
        if field and field in record:
            return json.dumps(record.get(field), ensure_ascii=False, sort_keys=True, default=str)
        return json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)

    @staticmethod
    def _emit(callback: Callable[[dict[str, Any]], None] | None, payload: dict[str, Any]) -> None:
        if callback is None:
            return
        try:
            callback(dict(payload))
        except (RuntimeError, TypeError, ValueError):
            return
