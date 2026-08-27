"""Stateful Playwright runtime handler for executable ``browser_action`` workflow nodes."""
from __future__ import annotations

import importlib.util
import logging
import time
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from arenyxa.domain.errors import ArenyxaError
from arenyxa.application.nextgen_browser import BrowserAction
from arenyxa.application.workflow_contract import validate_workflow_node
from arenyxa.domain.models import WorkflowNode

LOGGER = logging.getLogger(__name__)


class BrowserWorkflowActionHandler:
    """Execute a browser-action chain in one browser/page lifecycle per Workflow execution."""

    def __init__(self, browser_pool: Any | None = None, *, headless: bool = True) -> None:
        self.browser_pool = browser_pool
        self.headless = bool(headless)
        self._lease: Any | None = None
        self._playwright: Any | None = None
        self._browser: Any | None = None
        self._context: Any | None = None
        self._page: Any | None = None

    @staticmethod
    def dependency_available() -> bool:
        try:
            return importlib.util.find_spec("playwright.sync_api") is not None
        except (ImportError, ModuleNotFoundError, ValueError):
            return False

    @classmethod
    def runtime_available(cls) -> bool:
        if not cls.dependency_available():
            return False
        try:
            from playwright.sync_api import sync_playwright
            runtime = sync_playwright().start()
            try:
                return Path(runtime.chromium.executable_path).is_file()
            finally:
                runtime.stop()
        except (ImportError, OSError, RuntimeError):
            return False

    def begin_execution(self) -> None:
        if self._page is not None:
            raise RuntimeError("browser workflow execution lifecycle was already started")
        if not self.dependency_available():
            raise ArenyxaError(
                "BROWSER_RUNTIME_UNAVAILABLE",
                "Browser Workflow requires the Playwright browser extra and Chromium runtime",
                domain="WORKFLOW",
            )
        try:
            from playwright.sync_api import Error as PlaywrightError, sync_playwright
        except ImportError as exc:
            raise ArenyxaError(
                "BROWSER_RUNTIME_UNAVAILABLE",
                "Browser Workflow requires Playwright",
                domain="WORKFLOW",
            ) from exc
        if self.browser_pool is not None:
            self._lease = self.browser_pool.acquire(
                code="BROWSER_RESOURCE_LIMIT",
                message="Browser Workflow reached the configured browser instance limit",
            )
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=self.headless)
            self._context = self._browser.new_context(accept_downloads=True)
            self._page = self._context.new_page()
        except (OSError, RuntimeError, PlaywrightError) as exc:
            self.end_execution()
            raise ArenyxaError(
                "BROWSER_RUNTIME_START_FAILED",
                f"Browser Workflow could not start Chromium: {type(exc).__name__}: {exc}",
                domain="WORKFLOW",
            ) from exc

    def end_execution(self) -> None:
        page, context, browser, runtime, lease = self._page, self._context, self._browser, self._playwright, self._lease
        self._page = self._context = self._browser = self._playwright = self._lease = None
        for resource in (page, context, browser):
            if resource is not None:
                try:
                    resource.close()
                except Exception as exc:
                    LOGGER.warning("Browser Workflow cleanup failed for %s: %s", type(resource).__name__, exc)
                    continue
        if runtime is not None:
            try:
                runtime.stop()
            except Exception as exc:
                LOGGER.warning("Browser Workflow Playwright shutdown failed: %s", exc)
        if lease is not None:
            lease.release()

    def __call__(self, item: dict[str, Any], config: dict[str, Any]) -> Iterable[dict[str, Any]]:
        validate_workflow_node(WorkflowNode(kind="browser_action", config=dict(config), id="runtime-browser-action"))
        page = self._page
        if page is None:
            raise ArenyxaError(
                "BROWSER_RUNTIME_NOT_STARTED",
                "Browser Workflow runtime lifecycle is not active",
                domain="WORKFLOW",
            )
        action = BrowserAction(**dict(config))
        started = time.monotonic()
        result: dict[str, Any] = {"kind": action.kind}
        if action.kind == "goto":
            target = action.url or action.value
            parsed = urlparse(target)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("browser goto target must be an http/https URL")
            response = page.goto(target, timeout=action.timeout_ms, wait_until="domcontentloaded")
            result["status"] = None if response is None else response.status
        elif action.kind == "click":
            page.locator(action.selector).click(timeout=action.timeout_ms)
        elif action.kind == "fill":
            page.locator(action.selector).fill(action.value, timeout=action.timeout_ms)
        elif action.kind == "press":
            page.locator(action.selector).press(action.value, timeout=action.timeout_ms)
        elif action.kind == "check":
            page.locator(action.selector).check(timeout=action.timeout_ms)
        elif action.kind == "uncheck":
            page.locator(action.selector).uncheck(timeout=action.timeout_ms)
        elif action.kind == "select":
            selected = page.locator(action.selector).select_option(action.value, timeout=action.timeout_ms)
            result["selected"] = list(selected)
        elif action.kind == "wait":
            delay = max(0, min(action.timeout_ms, int(action.value or 0)))
            page.wait_for_timeout(delay)
            result["waited_ms"] = delay
        elif action.kind == "scroll":
            page.locator(action.selector or "body").evaluate("el => el.scrollIntoView()")
        elif action.kind == "upload":
            upload = Path(action.value).expanduser()
            if not upload.is_file():
                raise FileNotFoundError(str(upload))
            page.locator(action.selector).set_input_files(str(upload))
        elif action.kind == "download":
            with page.expect_download(timeout=action.timeout_ms) as info:
                page.locator(action.selector).click(timeout=action.timeout_ms)
            download = info.value
            result["suggested_filename"] = download.suggested_filename
            save_as = str(action.metadata.get("save_as", "")).strip()
            if save_as:
                destination = Path(save_as).expanduser().resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                download.save_as(str(destination))
                result["saved_to"] = str(destination)
        elif action.kind == "assert_text":
            actual = page.locator(action.selector).inner_text(timeout=action.timeout_ms)
            if action.value not in actual:
                raise AssertionError(f"assert_text failed: {action.value!r}")
            result["matched"] = True
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000.0, 3)
        result["url"] = str(page.url)
        return [{**item, "_browser_action_result": result}]
