from __future__ import annotations

import json
import re
from arenyxa.compat import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from lxml import etree, html

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CleanerStep, FetchResponse, FieldSpec
from arenyxa.infrastructure.safe_regex import safe_search, safe_sub


@dataclass(slots=True)
class ParsedDocument:
    kind: str
    value: Any
    source_text: str


class ParserRegistry:
    @staticmethod
    def parse(response: FetchResponse, hint: str = "auto") -> ParsedDocument:
        kind = hint.lower()
        if kind == "auto":
            content_type = response.content_type.lower()
            if "html" in content_type:
                kind = "html"
            elif "json" in content_type:
                kind = "json"
            elif "xml" in content_type or "rss" in content_type or "atom" in content_type:
                kind = "xml"
            else:
                stripped = response.body.lstrip()[:1]
                kind = "json" if stripped in {b"{", b"["} else "html"
        text = response.body.decode(response.encoding, errors="replace")
        try:
            if kind == "html":
                return ParsedDocument(kind, html.fromstring(text, base_url=response.final_url), text)
            if kind == "json":
                return ParsedDocument(kind, json.loads(text), text)
            if kind == "xml":
                parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=False)
                return ParsedDocument(kind, etree.fromstring(response.body, parser=parser), text)
        except (ValueError, etree.LxmlError) as exc:
            raise ArenyxaError("PARSE_INVALID", f"{kind.upper()} 解析失败：{exc}", domain="PARSE") from exc
        raise ArenyxaError("PARSE_UNSUPPORTED", f"不支持解析类型：{kind}", domain="PARSE")


class FieldExtractor:
    def extract(self, document: ParsedDocument, fields: list[FieldSpec]) -> tuple[dict[str, Any], list[str]]:
        record: dict[str, Any] = {}
        quality: list[str] = []
        for field in fields:
            try:
                values = self._select(document, field)
                raw: Any = values if field.multiple else (values[0] if values else field.default)
                cleaned = self._clean(raw, field.cleaners)
                converted = self._convert(cleaned, field.data_type)
                issues = self._validate(converted, field)
                quality.extend(f"{field.name}:{issue}" for issue in issues)
                record[field.name] = converted
            except Exception as exc:
                if isinstance(exc, ArenyxaError):
                    raise
                quality.append(f"{field.name}:extract_error")
                record[field.name] = field.default
        return record, quality

    def _select(self, document: ParsedDocument, field: FieldSpec) -> list[Any]:
        if document.kind == "html":
            if field.selector_type == "css":
                try:
                    nodes = document.value.cssselect(field.selector)
                except ImportError:
                                                                                         
                                                                                          
                                                                             
                    nodes = self._fallback_css(document.value, field.selector)
                except Exception as exc:
                    raise ArenyxaError(
                        "EXTRACT_SELECTOR_INVALID",
                        f"CSS 选择器无效：{field.selector}",
                        domain="EXTRACT",
                    ) from exc
            else:
                try:
                    nodes = document.value.xpath(field.selector)
                except etree.XPathError as exc:
                    raise ArenyxaError(
                        "EXTRACT_SELECTOR_INVALID",
                        f"XPath 无效：{field.selector}",
                        domain="EXTRACT",
                    ) from exc
            return [self._node_value(node, field) for node in nodes]
        if document.kind == "xml":
            try:
                nodes = document.value.xpath(field.selector)
            except etree.XPathError as exc:
                raise ArenyxaError("EXTRACT_SELECTOR_INVALID", str(exc), domain="EXTRACT") from exc
            return [self._node_value(node, field) for node in nodes]
        if document.kind == "json":
            return self._json_path(document.value, field.selector)
        return []

    @staticmethod
    def _fallback_css(document: Any, selector: str) -> list[Any]:
        selector = selector.strip()
                                                                                           
        match = re.fullmatch(
            r"(?P<tag>[A-Za-z][A-Za-z0-9_-]*|\*)?"
            r"(?P<id>#[A-Za-z0-9_.:-]+)?"
            r"(?P<classes>(?:\.[A-Za-z0-9_-]+)*)"
            r"(?P<attr>\[[A-Za-z_:][-A-Za-z0-9_:.]*(?:=[\"'][^\"']*[\"'])?\])?",
            selector,
        )
        if match is None:
            raise ArenyxaError(
                "EXTRACT_DEPENDENCY_MISSING",
                "完整 CSS 选择器需要 cssselect；当前恢复模式仅支持简单 CSS。",
                domain="EXTRACT",
                suggested_action="运行 Repair Center 安装 cssselect。",
            )
        tag = match.group("tag") or "*"
        clauses: list[str] = []
        if match.group("id"):
            clauses.append(f"@id={json.dumps(match.group('id')[1:])}")
        for cls in re.findall(r"\.([A-Za-z0-9_-]+)", match.group("classes") or ""):
            escaped = cls.replace("'", "&apos;")
            clauses.append(f"contains(concat(' ', normalize-space(@class), ' '), ' {escaped} ')")
        attr = match.group("attr")
        if attr:
            attr_match = re.fullmatch(r"\[([A-Za-z_:][-A-Za-z0-9_:.]*)(?:=[\"']([^\"']*)[\"'])?\]", attr)
            if attr_match:
                name, value = attr_match.groups()
                clauses.append(f"@{name}" if value is None else f"@{name}={json.dumps(value)}")
        predicate = f"[{' and '.join(clauses)}]" if clauses else ""
        try:
            return list(document.xpath(f"//{tag}{predicate}"))
        except etree.XPathError as exc:
            raise ArenyxaError("EXTRACT_SELECTOR_INVALID", f"CSS 选择器无效：{selector}", domain="EXTRACT") from exc

    @staticmethod
    def _node_value(node: Any, field: FieldSpec) -> Any:
        if isinstance(node, etree._Element):
            if field.target == "html":
                return etree.tostring(node, encoding="unicode", method="html")
            if field.target == "attribute" and field.attribute:
                return node.get(field.attribute)
            return " ".join(part.strip() for part in node.itertext() if part.strip())
        return node

    @staticmethod
    def _json_path(value: Any, path: str) -> list[Any]:
        normalized_path = path[1:] if path.startswith("$") else path
        tokens = [part for part in normalized_path.strip(".").split(".") if part]
        current = [value]
        for token in tokens:
            next_values: list[Any] = []
            for item in current:
                if token == "*":
                    if isinstance(item, dict):
                        next_values.extend(item.values())
                    elif isinstance(item, list):
                        next_values.extend(item)
                elif isinstance(item, dict) and token in item:
                    next_values.append(item[token])
                elif isinstance(item, list) and token.isdigit() and int(token) < len(item):
                    next_values.append(item[int(token)])
            current = next_values
        return current

    def _clean(self, value: Any, steps: list[CleanerStep]) -> Any:
        if isinstance(value, list):
            return [self._clean(item, steps) for item in value]
        result = value
        for step in steps:
            if not step.enabled:
                continue
            if step.kind == "trim" and isinstance(result, str):
                result = result.strip()
            elif step.kind == "normalize_whitespace" and isinstance(result, str):
                result = re.sub(r"\s+", " ", result).strip()
            elif step.kind == "empty_to_null" and result == "":
                result = None
            elif step.kind == "lower" and isinstance(result, str):
                result = result.lower()
            elif step.kind == "upper" and isinstance(result, str):
                result = result.upper()
            elif step.kind == "regex_extract" and isinstance(result, str):
                match = safe_search(str(step.options.get("pattern", "")), result)
                result = match.group(int(step.options.get("group", 0))) if match else None
            elif step.kind == "regex_replace" and isinstance(result, str):
                result = safe_sub(
                    str(step.options.get("pattern", "")),
                    str(step.options.get("replacement", "")),
                    result,
                )
            elif step.kind == "map":
                mapping = step.options.get("values", {})
                result = mapping.get(str(result), step.options.get("unknown", result))
        return result

    @staticmethod
    def _convert(value: Any, data_type: str) -> Any:
        if value is None or isinstance(value, list):
            return value
        if data_type == "string":
            return str(value)
        if data_type == "integer":
            return int(str(value).replace(",", ""))
        if data_type == "number":
            try:
                return float(Decimal(str(value).replace(",", "")))
            except InvalidOperation as exc:
                raise ValueError(f"无法转换为数字：{value}") from exc
        if data_type == "boolean":
            return str(value).strip().lower() in {"1", "true", "yes", "on", "是"}
        if data_type == "date":
            return datetime.fromisoformat(str(value)).date().isoformat()
        if data_type == "json":
            return json.loads(value) if isinstance(value, str) else value
        return value

    @staticmethod
    def _validate(value: Any, field: FieldSpec) -> list[str]:
        issues: list[str] = []
        if field.required and (value is None or value == "" or value == []):
            issues.append("required_missing")
        for rule in field.validators:
            if rule.kind == "regex" and value is not None:
                if not safe_search(str(rule.options.get("pattern", "")), str(value)):
                    issues.append("regex_mismatch")
            elif rule.kind == "range" and value is not None:
                minimum = rule.options.get("min")
                maximum = rule.options.get("max")
                if minimum is not None and value < minimum:
                    issues.append("below_minimum")
                if maximum is not None and value > maximum:
                    issues.append("above_maximum")
            elif rule.kind == "enum" and value not in rule.options.get("values", []):
                issues.append("not_in_enum")
        return issues
