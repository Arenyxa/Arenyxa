# Arenyxa v8.2.0 版本说明 / Release Notes

**产品：** Arenyxa  
**版本：** v8.2.0（短号 / display short：`8.2`）  
**发布通道：** stable  
**基线：** Arenyxa v8.1.1 handoff + Phase9 最小修复  
**promotion_source：** `v8.2_audit_fix_release_2026_09_10`  
**日期：** 2026-09-10（Asia/Shanghai）

---

## 概述 / Summary

Arenyxa **v8.2.0** 是在 **8.1.1 handoff** 源码树之上完成 Phase9 最小审计修复后的官方源码升版发布。本版统一消除历史 `8.1` / `8.1.0` / `8.1.1` 版本身份漂移，将产品内部版本全面对齐到 **8.2 / 8.2.0**，并保留 Win7 插件兼容线 `compatibility_identity = 6.8.0`。

Arenyxa **v8.2.0** is the official source release promoted from the **8.1.1 handoff** tree after Phase9 minimal audit fixes. It eliminates prior display/package/distribution version drift and aligns product identity to **8.2 / 8.2.0**, while keeping plugin/runtime compatibility at **6.8.0**.

---

## 本版变更 / Changes in v8.2.0

### Phase9 最小修复（已合入基线）

| ID / 主题 | 说明 |
|-----------|------|
| **BUG-NEW-001** | `revoke_device`：设备缺失时抛出 `ArenyxaError(DEVICE_INVALID)`，与 kernel / `disable_identity` 语义对齐 |
| **JobLifecycle** | `start_job` 失败时先 `fail(..., JOB_START_FAILED, retryable=True)` 再向上抛出，避免租约悬挂 |
| **experience 契约** | `apply_experience_profile("developer")` 不得强制 `developer_nav_expanded=True` |
| **crawler_intelligence contract** | `nextgen.crawler_intelligence` 功能契约补齐 |

### 版本身份对齐（消除漂移）

- `__version__`（short / display）→ `8.2`
- `__package_version__` / `pyproject.toml` `version` → `8.2.0`
- `__display_version__` / `__distribution_version__` / `__engineering_build__` → `8.2.0` / `v8.2.0`
- Windows `filevers`/`prodvers` → `(8,2,0,0)`；`windows_file_version` → `8.2.0.0`
- 安装包：`Arenyxa_V8.2.0_Setup_x64` / `Arenyxa_V8.2.0_Legacy_Win7_x64_Setup`
- `artifact_name`：`Arenyxa_v8.2`
- **未改** `compatibility_identity`：仍为 `6.8.0`（Win7 / 插件兼容线）

---

## 版本身份表 / Release Identity Table

| 字段 | 值 |
|------|-----|
| display / `__version__` | `8.2` |
| `__package_version__` / pyproject `version` | `8.2.0` |
| `__display_version__` / `__distribution_version__` | `8.2.0` |
| `__engineering_build__` | `v8.2.0` |
| `windows_file_version` | `8.2.0.0` |
| version_info filevers/prodvers | `(8,2,0,0)` |
| `artifact_name` | `Arenyxa_v8.2` |
| installer OutputBaseFilename | `Arenyxa_V8.2.0_*` |
| `compatibility_identity` | `6.8.0`（不变） |
| `baseline` | `Arenyxa_v8.1.1` |
| `promotion_source` | `v8.2_audit_fix_release_2026_09_10` |
| `release_channel` | `stable` |

权威文件：`RELEASE_IDENTITY.json`、`V8_2_RELEASE_IDENTITY.json`（`V8_1_RELEASE_IDENTITY.json` 保留作历史）。

---

## 已知限制 / Known Limitations

- **Windows 原生门禁**（Npcap/ETW/WFP/DPAPI/TPM-CNG/SCM、Inno 实装）：本 Linux 审计环境不可执行，记为 `NOT EXECUTED` / `BLOCKED`。
- **PostgreSQL 多节点 / 分布式失败演练**：依赖外部 PG 与多机环境，本树未宣称生产多节点认证完成。
- **GUI / Qt 完整交互**：无头/无完整 GUI 资源时仅做源码与单元层验证。
- **Packaging 二进制产物**：源码发布不附带伪造的 `.exe`/安装包二进制；需在 Windows 构建机用 `scripts/build.ps1` 生成。
- 历史 `audit_out/` 审计报告保留为验收证据，不回溯改写。

详见：`audit_out/REMAINING_RISK_REGISTER.md`、`audit_out/ARENYXA_FINAL_ENGINEERING_CERTIFICATION.md`。

---

## 兼容性 / Compatibility

- 插件与运行时兼容身份仍为 **`6.8.0`**。
- Win7 为功能冻结的 legacy lane（`legacy/win7/`）。
- 自 8.1.1 → 8.2.0 为版本身份与审计修复升版，非数据库 schema 破坏性迁移。

---

## 验证建议 / Verification

```bash
PYTHONPATH=src python -c "from arenyxa import __version__, __package_version__, __display_version__; print(__version__, __package_version__, __display_version__)"
# 期望: 8.2 8.2.0 8.2.0

python scripts/verify_v82_release_identity.py
```
