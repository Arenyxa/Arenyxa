from __future__ import annotations

from arenyxa.compat import dataclass


DEVELOPER_TERMS_VERSION = 1

RISK_AGREEMENT_TITLE = "开发者风险协议"
RISK_AGREEMENT_TEXT = (
    "Developer Mode 会开放高级诊断、受控外部命令、完整功能验证和高负载稳定性测试。\n\n"
    "启用后，测试可能显著提高 CPU、内存、磁盘与本地网络回环负载，并可能触发可选组件、驱动或安全软件的行为。"
    "完整功能验证默认使用隔离临时目录与 127.0.0.1 回环服务，不会主动访问公网目标；高负载测试也不会主动写入正式项目数据。\n\n"
    "仅在你拥有或获准测试的设备与数据环境中使用这些能力。测试期间请保存正在编辑的工作，发现异常时立即停止。"
)

WAIVER_TITLE = "测试免责协议"
WAIVER_TEXT = (
    "开发者测试用于发现缺陷、性能边界与稳定性问题，不构成对特定硬件、驱动、第三方组件或极端负载条件的无故障保证。\n\n"
    "高负载测试采用有界压力模型：它会逐级提高并发并在检测到错误、资源异常或达到内置安全上限时停止，"
    "不会以故意耗尽系统内存、填满磁盘或使操作系统失去响应为目标。\n\n"
    "继续即表示你理解上述风险，并同意自行判断当前设备是否适合执行开发者测试。"
)


@dataclass(frozen=True, slots=True)
class DeveloperAuthorization:
    developer_mode: bool
    accepted_version: int
    accepted_at: str

    @property
    def valid(self) -> bool:
        return bool(
            self.developer_mode
            and self.accepted_version >= DEVELOPER_TERMS_VERSION
            and isinstance(self.accepted_at, str)
            and self.accepted_at.strip()
        )


def authorization_from_settings(settings: object) -> DeveloperAuthorization:
    version_raw = getattr(settings, "developer_terms_version", 0)
    try:
        version = int(version_raw)
    except (TypeError, ValueError, OverflowError):
        version = 0
    accepted_at = getattr(settings, "developer_terms_accepted_at", "")
    return DeveloperAuthorization(
        developer_mode=bool(getattr(settings, "developer_mode", False)),
        accepted_version=max(0, version),
        accepted_at=str(accepted_at or ""),
    )
