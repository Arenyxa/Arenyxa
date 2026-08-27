# Arenyxa V6.0 需求追踪矩阵

| 需求范围 | 设计/实现证据 | 验证证据 |
|---|---|---|
| FR-APP-001..008 | `app.py`, `main_window.py`, `single_instance.py`, `config.py` | UI smoke、打包 EXE smoke、安全关闭标记 |
| FR-TASK/REQ/FETCH | `models.py`, `tasks.py`, `runner.py`, `http_client.py` | Domain、mock HTTP、任务/Run SQLite 测试 |
| FR-PARSE/FIELD/CLEAN/PREV | `parsers.py`, `runner.py`, `tasks.py` | HTML/JSON/XML、CSS/JSON Path、清洗和类型转换测试 |
| FR-DATA/EXP/SEARCH | `database.py`, `data.py`, `export.py` | 分页、FTS5、CSV/JSON/JSONL/XLSX 流式导出测试 |
| FR-RUN/AUTO | `runner.py`, `scheduler.py`, `tools.py` | 状态持久化、时区、重启恢复与到期触发测试 |
| FR-OBS/SEC | `observability.py`, `errors.py`, `permissions.py` | 深层脱敏、稳定错误、RBAC 与诊断检查 |
| FR-THEME/SET | `themes.py`, `settings.py`, `language.py` | 六主题状态保持、10 locale、RTL、Windows 字体截图 |
| FR-V6-071..079 | `capture/*`, `network.py`, `advanced.py` | HAR、Filter、Backpressure、Dropped、Browser Chromium 实测、TLS/DNS/Replay 单元路径 |
| FR-V6-080..087 | `advanced.py`, `versioning.py`, `database_adapters.py`, `visualization.py` | Planner/API Map/Map/Performance/Security、Revision、SQLite/SQLAlchemy 实测、PNG 截图 |
| FR-V6-088 | `project_format.py` | SHA-256、秘密排除、Zip Slip 与 Archive Limit 测试 |
| FR-V6-089..090 | `server.py`, `permissions.py`, Docker 文件 | FastAPI health/auth/task listing 测试，loopback 默认 |
| FR-V6-091 | `runtime_ecosystem.py` | HTTPS 目录、校验和、安装副本的服务契约审查 |
| FR-V6-092 | `application/terminal.py`, `tools.py` ConsolePage | 多执行模式、实时输出/停止、cwd/env/history、只读 SQL、输出/超时边界、秘密脱敏、Developer Mode 与逐次确认；`test_terminal_hardening.py` |
| FR-V6-093 | `workflows.py`, WorkflowPage | 正常边、失败边、校验错误路由测试 |
| FR-V6-094..095 | `runtime_ecosystem.py`, `capture/adapters.py` | 回归比较服务、隔离 Browser Profile、DOM Snapshot 实测 |
| FR-V6-096 | `plugins.py`, `plugin_worker.py` | Manifest、未知权限、授权拒绝、超时/输出/Job Object 代码路径测试 |
| FR-V6-097..100 | `themes.py`, `glass.py` | Aurora/Light/Dark/Graphite/Terminal/Blue 语义 Token 与 Windows 截图 |
| FR-V6-101..106 | `motion.py`, `glass.py`, `main_window.py` | Spring 收敛、动画完成清理、Edge Flow 与集中 Intent 路径 |
| FR-V6-107..112 | `motion.py`, `settings.py` | PreciseTimer、120Hz 帧预算、质量降级、Reduce Motion、持久化测试 |

说明：兼容的 packet-analysis runtime 与 packet-capture driver 属于系统依赖，不进入源码包；无驱动时返回 `CAPTURE_DRIVER_MISSING`，不会伪造抓包结果或回退为不同语义的实现。
