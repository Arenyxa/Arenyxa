# Arenyxa 测试与验证

## 常用入口

```powershell
.\.venv\Scripts\python.exe -B .\scripts\verify_release_identity.py
.\scripts\test.ps1
```

测试入口覆盖静态/契约检查、单元与 SQLite、集成与生命周期、Repair Center、企业队列/租约以及专用 PostgreSQL 回归。破坏性数据库夹具必须保持隔离并单独记录。

## v0.1 发布证据摘要

- 冻结候选 `full_08`：1,869 passed、3 skipped、1 failed、1 deselected；唯一 failure 为旧的“已批准图标”SHA-256 预期值。
- 2026-10-04，Release Owner 明确批准当前 `src/arenyxa/resources/icons/arenyxa.png`，SHA-256 为 `EAF8A3F0D8B0AFEA1411F73C495764ECCF5167C69A72F01323ADAB60CBCC51F5`；更新批准记录后对应门禁单测通过。
- 必需 PostgreSQL 实时回归 7 项通过；本地有界 P99 验证记录为 32w/32c 100.787 ms、64w/128c 185.558 ms。
- 已有代表性打包 GUI 自动验收；Release Owner 另行确认已完成人工 GUI 验收。人工结果不冒充自动化结果。
- 24 小时 soak 被 Release Owner 明确改为 deferred / non-blocking，不记录为 passed。
- 独立 clean-Windows 安装、升级、回滚和卸载资格不由本次源码发布声明。

当前发布范围和限制见 [Release Status](RELEASE_STATUS.md)。
