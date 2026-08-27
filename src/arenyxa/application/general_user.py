from __future__ import annotations
from arenyxa.recoverable import record_current_exception

"""Task-oriented UX and runtime resilience for Arenyxa's Personal experience profile.

This layer does not grant capabilities or change Professional/Developer behavior.  It turns
common user goals into bounded guided workflows and reports optional-runtime degradation
without treating external tools as mandatory for the whole product.
"""

import importlib.util
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from arenyxa.compat import dataclass
from arenyxa.config import AppSettings
from arenyxa.infrastructure.external_tools import ExternalToolProbe


@dataclass(frozen=True, slots=True)
class RuntimeCapability:
    id: str
    title: str
    state: str
    backend: str
    detail: str
    fallback: str = ""
    executable: str = ""

    @property
    def available(self) -> bool:
        return self.state in {"ready", "native", "degraded"}

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class RuntimeCapabilityService:
    """Detect optional runtimes and expose explicit native/built-in fallbacks."""

    def snapshot(self) -> dict[str, RuntimeCapability]:
        probes = (self._packet_deep, self._system_capture, self._mitm, self._browser)
        with ThreadPoolExecutor(max_workers=len(probes), thread_name_prefix="ArenyxaCapability") as pool:
            futures = [pool.submit(probe) for probe in probes]
            rows = [self._packet_native(), *[future.result() for future in futures]]
        return {row.id: row for row in rows}

    @staticmethod
    def _packet_native() -> RuntimeCapability:
        return RuntimeCapability(
            "packet.native", "Native PCAP / protocol analysis", "native", "arenyxa-native",
            "Dependency-free PCAP/PCAPNG reader and bounded native protocol decoder are available.",
        )

    @classmethod
    def _packet_deep(cls) -> RuntimeCapability:
        probe = ExternalToolProbe.tshark()
        return RuntimeCapability(
            "packet.deep", "Deep packet dissector", "ready" if probe.usable else "degraded",
            "tshark" if probe.usable else "arenyxa-native",
            f"TShark {probe.version} passed the compatibility contract." if probe.usable else
            f"TShark unavailable/incompatible ({probe.detail}); native decoding remains available.",
            "arenyxa-native", probe.executable,
        )

    @classmethod
    def _system_capture(cls) -> RuntimeCapability:
        tshark = ExternalToolProbe.tshark()
        dumpcap = ExternalToolProbe.dumpcap()
        usable = tshark.usable
        backend = "dumpcap+tshark" if usable and dumpcap.usable else ("tshark" if usable else "none")
        return RuntimeCapability(
            "capture.system", "System packet capture", "ready" if usable and dumpcap.usable else ("degraded" if usable else "unavailable"),
            backend, "System capture compatibility contract passed." if usable else
            "System capture runtime is unavailable/incompatible; offline PCAP analysis is unaffected.",
            "packet.native", dumpcap.executable if dumpcap.usable else tshark.executable,
        )

    @classmethod
    def _mitm(cls) -> RuntimeCapability:
        probe = ExternalToolProbe.mitmdump()
        return RuntimeCapability(
            "mitm.external", "Advanced MITM automation", "ready" if probe.usable else "unavailable",
            "mitmdump" if probe.usable else "none",
            f"mitmdump {probe.version} passed the compatibility contract." if probe.usable else
            f"mitmdump unavailable/incompatible ({probe.detail}); built-in HTTP/API analysis remains available.",
            "proxy+builtin-analysis", probe.executable,
        )

    @classmethod
    def _browser(cls) -> RuntimeCapability:
        try:
            installed = importlib.util.find_spec("playwright.sync_api") is not None
        except (ImportError, ModuleNotFoundError, AttributeError, ValueError):
            installed = False
        ready, path = cls._playwright_browser_state() if installed else (False, "")
        state = "ready" if ready else ("degraded" if installed else "unavailable")
        return RuntimeCapability(
            "browser.automation", "Browser automation", state,
            "playwright+chromium" if ready else ("playwright" if installed else "none"),
            "Playwright Chromium is ready." if ready else
            "Browser automation is not fully ready; HTTP/API inspection and imported HAR analysis remain available.",
            "http+har", path,
        )

    @staticmethod
    def _playwright_browser_state() -> tuple[bool, str]:
        try:
            from playwright.sync_api import sync_playwright
        except (ImportError, ModuleNotFoundError):
            return False, ""
        runtime = None
        try:
            runtime = sync_playwright().start()
            path = str(runtime.chromium.executable_path or "")
            return bool(path and Path(path).is_file() and os.access(path, os.X_OK)), path
        except (OSError, RuntimeError, ValueError):
            return False, ""
        finally:
            if runtime is not None:
                try:
                    runtime.stop()
                except (OSError, RuntimeError):
                    record_current_exception(__name__, 'RuntimeCapabilityService._playwright_browser_state:129')


@dataclass(frozen=True, slots=True)
class GuidedWorkflow:
    id: str
    title: str
    summary: str
    page_id: str
    steps: tuple[str, ...]
    aliases: tuple[str, ...]
    required_capabilities: tuple[str, ...] = ()
    fallback_note: str = ""
    auto_action: str = ""


WORKFLOWS: tuple[GuidedWorkflow, ...] = (
    GuidedWorkflow(
        "live_network", "Analyze Network Traffic", "查看电脑正在连接什么服务器和协议。", "network",
        ("选择可用捕获方式", "开始捕获", "实时协议/主机统计", "异常检测", "生成简明结果"),
        ("网络流量", "实时网络", "连接服务器", "连接了哪些服务器", "电脑连接", "network traffic", "live traffic"),
        ("capture.system",), "系统抓包不可用时可切换 Browser Capture 或 PCAP/HAR。", "prepare_capture",
    ),
    GuidedWorkflow(
        "capture_traffic", "Capture Traffic", "开始实时抓包，自动选择当前可用的捕获方式。", "network",
        ("检查捕获能力", "自动选择 System/Browser", "开始捕获", "实时统计", "停止后生成摘要"),
        ("抓包", "开始抓包", "捕获流量", "实时抓包", "capture", "capture traffic", "start capture"),
        ("capture.system",), "System Capture 不可用时尝试 Browser Capture；仍可导入 PCAP/HAR。", "prepare_capture",
    ),
    GuidedWorkflow(
        "analyze_pcap", "Analyze a PCAP File", "导入 PCAP/PCAPNG 并自动分析协议与异常。", "network",
        ("选择 PCAP/PCAPNG", "原生格式读取", "协议解析", "Conversation 分析", "Passive Detection", "风险摘要"),
        ("pcap", "pcapng", "分析抓包", "抓包文件", "packet file", "analyze pcap"),
        ("packet.native",), "TShark 不存在或失效时自动使用 Arenyxa native decoder。", "import_pcap",
    ),
    GuidedWorkflow(
        "security_check", "Security Check", "自动查看可疑连接、DNS、TLS 与行为异常。", "task_center",
        ("读取最近流量", "Passive Detection", "Threat Hunt", "DNS/TLS 检查", "风险分级", "展示重点发现"),
        ("安全检查", "异常连接", "dns隧道", "威胁", "security check", "threat", "suspicious"),
        (), "没有外部分析器也可使用内置 Detection / Threat Hunter。", "security_check",
    ),
    GuidedWorkflow(
        "debug_api", "Debug an API", "分析 HTTP/HTTPS API 请求、响应与安全问题。", "network",
        ("准备请求/历史流量", "检查 Header/状态码", "TLS/API 分析", "重放/对比", "结果摘要"),
        ("api", "接口", "调试接口", "debug api", "请求响应"),
        (), "高级 MITM 不可用时仍保留内置 API/HTTP 分析和代理调试。", "open_api",
    ),
    GuidedWorkflow(
        "inspect_website", "Inspect a Website", "分析网站请求、API、资源和页面结构。", "tasks",
        ("输入目标", "选择 Browser/HTTP 路径", "采集请求", "结构分析", "提取候选", "结果摘要"),
        ("网站", "网页", "website", "分析网站", "页面结构", "网页抓取"),
        ("browser.automation",), "Chromium 不可用时保留 HTTP/HAR 路径。", "open_extraction",
    ),
    GuidedWorkflow(
        "diagnose_network", "Diagnose a Network Problem", "检查连接、DNS、TLS 和本地运行能力。", "task_center",
        ("检查运行状态", "进程/网络能力", "DNS/TLS 路径", "外部组件状态", "给出下一步"),
        ("网络故障", "网络诊断", "dns问题", "tls问题", "连不上", "diagnose network", "network problem"),
        (), "诊断明确区分内置能力和可选外部组件。", "network_diagnose",
    ),
    GuidedWorkflow(
        "open_project", "Open Existing Project", "验证并打开现有 .arenyxa 项目。", "dashboard",
        ("选择项目", "完整性验证", "读取 Manifest", "打开工作区"),
        ("打开项目", "项目文件", "arenyxa project", "open project"), (), "", "open_project",
    ),
)

_WORKFLOW_BY_ID = {item.id: item for item in WORKFLOWS}


def is_general_user(settings: AppSettings) -> bool:
    """Personal profile alone receives Simple Mode; other profiles are unchanged."""
    return str(getattr(settings, "experience_profile", "") or "").casefold() == "personal"


class GeneralUserIntentRouter:
    """Deterministic local intent router used by Simple Mode and Ctrl+K."""

    def workflows(self) -> tuple[GuidedWorkflow, ...]:
        return WORKFLOWS

    def get(self, workflow_id: str) -> GuidedWorkflow:
        key = str(workflow_id or "").strip().casefold()
        if key not in _WORKFLOW_BY_ID:
            raise ValueError(f"unknown general-user workflow: {workflow_id}")
        return _WORKFLOW_BY_ID[key]

    def resolve(self, text: str) -> GuidedWorkflow | None:
        query = " ".join(str(text or "").casefold().strip().split())[:1024]
        if not query:
            return None
        ranked = [(self._score(query, item), item) for item in WORKFLOWS]
        score, workflow = max(ranked, key=lambda row: row[0])
        return workflow if score >= 3 else None

    @staticmethod
    def _score(query: str, workflow: GuidedWorkflow) -> int:
        title = workflow.title.casefold()
        if query in {workflow.id, title}:
            return 100
        score = 8 if query in title or title in query else 0
        for alias in workflow.aliases:
            token = alias.casefold()
            score += 12 if token == query else (5 if token and token in query else 0)
        for term in re.findall(r"[a-z0-9]+|[\u3400-\u9fff]{2,}", query):
            if term in title or any(term in alias.casefold() for alias in workflow.aliases):
                score += 1
        return score


@dataclass(frozen=True, slots=True)
class GeneralUserFinding:
    severity: str
    title: str
    detail: str


@dataclass(frozen=True, slots=True)
class GeneralUserSummary:
    risk: str
    score: int
    event_count: int
    host_count: int
    protocol_count: int
    top_protocols: tuple[tuple[str, int], ...]
    findings: tuple[GeneralUserFinding, ...]

    def snapshot(self) -> dict[str, Any]:
        return {
            "risk": self.risk, "score": self.score, "event_count": self.event_count,
            "host_count": self.host_count, "protocol_count": self.protocol_count,
            "top_protocols": [list(item) for item in self.top_protocols],
            "findings": [asdict(item) for item in self.findings],
        }


def summarize_network_events(events: Iterable[Mapping[str, Any]], *, limit: int = 50_000) -> GeneralUserSummary:
    """Generate a conservative general-user risk summary from normalized event metadata."""
    protocols: Counter[str] = Counter()
    hosts: set[str] = set()
    counts = Counter()
    total = 0
    for row in events:
        if total >= max(1, min(200_000, int(limit))):
            break
        total += 1
        protocol = str(row.get("protocol") or "unknown").casefold()
        protocols[protocol] += 1
        host = str(row.get("host") or "").strip()
        if host and len(hosts) < 100_000:
            hosts.add(host)
        _accumulate_risk_counts(row, protocol, counts)
    score, findings = _score_findings(counts)
    risk = "High" if score >= 60 else ("Medium" if score >= 30 else "Low")
    if not findings:
        findings.append(GeneralUserFinding("info", "未发现明显高风险信号", "当前摘要未发现内置规则能够确认的高风险模式。"))
    return GeneralUserSummary(risk, score, total, len(hosts), len(protocols), tuple(protocols.most_common(8)), tuple(findings[:12]))


def _accumulate_risk_counts(row: Mapping[str, Any], protocol: str, counts: Counter[str]) -> None:
    url = str(row.get("url") or "").casefold()
    headers = row.get("request_headers") or {}
    flags = row.get("sensitivity_flags") or row.get("sensitivity") or []
    metadata = row.get("metadata") or {}
    status = row.get("status")
    if url.startswith("http://"):
        counts["clear_http"] += 1
        sensitive_names = {"authorization", "cookie", "x-api-key", "proxy-authorization"}
        if flags or any(str(name).casefold() in sensitive_names for name in headers):
            counts["sensitive_http"] += 1
    tls = str(metadata.get("tls_version") or metadata.get("tls.record.version") or "").casefold() if isinstance(metadata, Mapping) else ""
    if any(marker in tls for marker in ("ssl", "tlsv1.0", "tls 1.0", "tlsv1.1", "tls 1.1")):
        counts["legacy_tls"] += 1
    if isinstance(status, int) and status >= 500:
        counts["server_errors"] += 1
    if protocol in {"dns", "doh", "dot", "doq"} and isinstance(metadata, Mapping):
        name = str(metadata.get("dns_name") or metadata.get("query") or metadata.get("qname") or "")
        if len(name) > 120 or any(len(part) > 45 for part in name.split(".")):
            counts["dns_suspicious"] += 1


def _score_findings(counts: Counter[str]) -> tuple[int, list[GeneralUserFinding]]:
    score = 0
    findings: list[GeneralUserFinding] = []
    if counts["sensitive_http"]:
        score += 45
        findings.append(GeneralUserFinding("high", "发现明文敏感 HTTP", f"{counts['sensitive_http']} 条请求可能在未加密 HTTP 上传输敏感信息。"))
    elif counts["clear_http"]:
        score += min(15, 3 + counts["clear_http"] // 20)
        findings.append(GeneralUserFinding("low", "存在明文 HTTP", f"观察到 {counts['clear_http']} 条 HTTP 请求；建议优先使用 HTTPS。"))
    if counts["legacy_tls"]:
        score += min(30, 10 + counts["legacy_tls"] * 2)
        findings.append(GeneralUserFinding("medium", "发现旧版 TLS/SSL", f"观察到 {counts['legacy_tls']} 条旧版 TLS/SSL 元数据。"))
    if counts["dns_suspicious"]:
        score += min(25, 8 + counts["dns_suspicious"])
        findings.append(GeneralUserFinding("medium", "DNS 名称值得检查", f"{counts['dns_suspicious']} 条 DNS 名称长度异常；这不是恶意行为的确定证据。"))
    if counts["server_errors"] >= 10:
        score += min(15, counts["server_errors"] // 10)
        findings.append(GeneralUserFinding("low", "服务器错误较多", f"观察到 {counts['server_errors']} 条 5xx 响应。"))
    return max(0, min(100, score)), findings


__all__ = [
    "GeneralUserFinding", "GeneralUserIntentRouter", "GeneralUserSummary", "GuidedWorkflow",
    "RuntimeCapability", "RuntimeCapabilityService", "WORKFLOWS", "is_general_user", "summarize_network_events",
]
