from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from arenyxa.application.adaptive_extraction import AdaptiveExtractionEngine, AdaptiveSelectorStore
from arenyxa.application.browser_engine import BrowserPool


def test_adaptive_selector_remember_and_stable(tmp_path: Path) -> None:
    store = AdaptiveSelectorStore(tmp_path / "selectors.json")
    engine = AdaptiveExtractionEngine(store)
    html = '<html><body><div class="product-card" data-testid="product">Alpha</div></body></html>'
    version = engine.remember("example.test", "product", html, '.product-card')
    result = engine.resolve("example.test", "product", html, auto_apply=True)
    assert result["status"] == "stable"
    assert result["selected"]["version_id"] == version.version_id


def test_adaptive_selector_heals_and_creates_version_edge(tmp_path: Path) -> None:
    store = AdaptiveSelectorStore(tmp_path / "selectors.json")
    engine = AdaptiveExtractionEngine(store)
    old = '<html><body><main><div class="product-card" data-testid="product">Alpha Product</div></main></body></html>'
    new = '<html><body><main><div class="item-wrapper" data-testid="product">Alpha Product</div></main></body></html>'
    original = engine.remember("example.test", "product", old, '.product-card')
    result = engine.resolve("example.test", "product", new, min_confidence=.80, auto_apply=True)
    assert result["status"] == "healed"
    versions = store.versions("example.test", "product")
    assert len(versions) == 2
    assert versions[-1].parent_version_id == original.version_id
    assert versions[-1].selector != original.selector


def test_low_confidence_does_not_silently_apply(tmp_path: Path) -> None:
    store = AdaptiveSelectorStore(tmp_path / "selectors.json")
    engine = AdaptiveExtractionEngine(store)
    engine.remember("example.test", "price", '<div><span class="price">$10</span></div>', '.price')
    result = engine.resolve("example.test", "price", '<div><button>Completely unrelated</button></div>', auto_apply=True)
    assert result["status"] == "review-required"
    assert result["selected"] is None


def test_selector_store_persists_version_graph(tmp_path: Path) -> None:
    path = tmp_path / "selectors.json"
    engine = AdaptiveExtractionEngine(AdaptiveSelectorStore(path))
    engine.remember("example.test", "title", '<h1 data-testid="title">Hello</h1>', 'h1')
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert sum(len(v) for v in payload["selectors"].values()) == 1
    assert len(AdaptiveSelectorStore(path).versions("example.test", "title")) == 1


def test_resolve_pins_selected_version_against_concurrent_pruning(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingStudio:
        def analyze(self, _markup: str, selector: str, _selector_type: str):
            if selector == ".selected":
                entered.set()
                assert release.wait(3.0)
                return {"matches": 1, "fingerprint": {"tag": "div"}}
            return {"matches": 1, "fingerprint": {"tag": "div"}}

    store = AdaptiveSelectorStore(tmp_path / "selectors-race.json", max_versions_per_key=4)
    for index in range(3):
        store.remember("example.test", "item", f".old-{index}", "css", {"tag": "div", "i": index})
    selected = store.remember("example.test", "item", ".selected", "css", {"tag": "div", "i": 3})
    engine = AdaptiveExtractionEngine(store, studio=BlockingStudio())  # type: ignore[arg-type]
    outcome: dict[str, object] = {}

    def resolve() -> None:
        try:
            outcome["result"] = engine.resolve("example.test", "item", "<div></div>")
        except Exception as exc:  # noqa: BLE001 - thread relays every regression failure
            outcome["error"] = exc

    worker = threading.Thread(target=resolve, daemon=True)
    worker.start()
    assert entered.wait(2.0)
    for index in range(4, 8):
        store.remember("example.test", "item", f".new-{index}", "css", {"tag": "div", "i": index})
    release.set()
    worker.join(3.0)

    assert not worker.is_alive()
    assert "error" not in outcome
    assert outcome["result"]["status"] == "stable"  # type: ignore[index]
    retained = {item.version_id: item for item in store.versions("example.test", "item")}
    assert retained[selected.version_id].success_count == 1


def test_browser_pool_validates_capacity_without_playwright_launch() -> None:
    with pytest.raises(ValueError):
        BrowserPool(max_contexts=0)
    pool = BrowserPool(max_contexts=2)
    assert pool.max_contexts == 2
    pool.close()
