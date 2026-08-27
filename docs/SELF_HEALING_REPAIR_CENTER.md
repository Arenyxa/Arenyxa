# Arenyxa V6.0 — Self-Healing Repair Center / 自愈修复中心

## 启动行为

每次正常启动 Arenyxa 都会在业务上下文初始化前执行一次**只读优先的健康扫描**。扫描内容包括：

- 上次是否异常退出 / 崩溃循环迹象；
- `settings.json` UTF-8、JSON、语言与主题配置；
- 数据目录、数据库、缓存、日志目录的可写状态；
- SQLite `PRAGMA quick_check`、WAL / FTS 基础健康；
- PySide6、lxml、cssselect、dnspython、openpyxl、tzdata 等核心依赖；
- 当前安装目录程序文件完整性；
- 最近日志中的编码、依赖、数据库、插件、抓包、权限、服务、渲染异常；
- 磁盘空间与异常膨胀缓存。

打包版不会在每次启动都对整个安装目录做数百 MB 的完整哈希：**每次启动检查所有文件是否存在/尺寸是否正确，并对关键运行时文件做 SHA-256；每 24 小时或异常退出后执行一次全量 SHA-256 深度校验。**

如果检测到异常，Arenyxa 会先询问用户“软件是否存在问题 / 是否进入修复中心”。选择 **是** 后进入问题类型选择页：

- **自动检测并修复（推荐）**：根据健康报告自动选择修复项目；
- **手动选择问题类型**：可多选一个或多个问题类型。

随后 Arenyxa 主界面退出，独立的 **Arenyxa Repair Center** 终端自动启动。用户不需要输入任何命令，流程为：

`等待主程序退出 → 备份 → 恢复程序文件 → 修复配置/数据库/插件/缓存/运行时 → 完整性复验 → 重启 Arenyxa → 终端自动退出`

## 问题类型

1. 乱码 / 语言 / 字体显示异常
2. 启动失败 / 崩溃 / 闪退 / 崩溃循环
3. 程序文件缺失 / 损坏 / 被意外修改
4. Python / Qt / 模块依赖加载异常
5. SQLite 数据库 / FTS 索引 / WAL 异常
6. 设置 / 主题 / 窗口布局异常
7. 插件加载 / 权限 / 插件崩溃异常
8. 抓包 / tshark / dumpcap / 进程监控异常
9. 目录 / 权限 / 写入 / 存储路径异常
10. 缓存 / 临时文件 / 残留状态异常
11. 本地服务 / 端口 / 运行时异常
12. 动画 / 渲染 / 卡顿 / 性能配置异常
13. 其他 / 无法确定的问题

## 自动修复策略

- **乱码/语言**：恢复合法 locale、UTF-8 设置和字体/语言 fallback，不覆盖用户正式数据。
- **崩溃/闪退**：清理 crash marker 与安全临时状态、检查插件和程序完整性，并恢复稳定启动参数。
- **程序文件**：Windows 打包版由安装目录外的独立 PowerShell Worker 等待 Arenyxa 完全退出后，从本地离线恢复包覆盖缺失/损坏文件，再逐文件做 SHA-256 验证。
- **依赖**：源码开发环境可用 `pip` 非交互恢复 Python 依赖；打包版依赖由离线程序恢复包还原，不在线下载未知二进制。
- **数据库/FTS**：先备份；健康数据库执行 checkpoint / reindex / FTS 优化；损坏数据库保留原件后尝试重建，只有新库通过 `quick_check` 才替换。
- **设置/主题**：只规范损坏或越界字段，保留其他合法用户设置。
- **插件**：异常插件隔离/禁用而不是删除；正式数据不随插件修复清理。
- **抓包**：检查 Python 侧运行环境和 tshark/dumpcap 可用性；不会静默安装第三方 packet-analysis runtime 或 packet-capture driver。
- **权限/路径**：检查并恢复 Arenyxa 自身数据目录的可写状态，不对任意系统目录做宽泛权限修改。
- **缓存**：只清理可再生成缓存/临时状态，不删除 Projects、Captures、Exports 或正式结果。
- **服务/端口**：诊断本地 Server 环境，不因为 8787 被占用就强行结束未知进程。
- **动画/性能**：恢复 Balanced 稳定基线、Reduce Motion/Glass 参数合法值；不会加入屏幕跑马灯或电源键呼出动画。

## 安全不变量

- `projects`、`captures`、`exports` 和正式结果记录不会被缓存修复删除。
- 任何会修改配置或数据库的动作先创建备份。
- 程序文件只能从当前发布版本的**本地离线恢复包**恢复，并在复制前后校验 SHA-256；修复工具不会“现场生成”任意替代源码。
- 恢复包中的 ZIP 路径必须通过 traversal 检查；不允许绝对路径、盘符或 `..` 逃逸安装根目录。
- 修复终端使用固定内部脚本，不接受用户输入的任意 Shell 命令。
- 插件异常采用隔离策略；数据库异常采用保留原件策略。
- 端口冲突不会触发未知进程强杀。
- 修复失败时保留日志和备份，不以“删除全部用户数据”作为自动兜底。

## 修复工件

应用数据目录：

```text
repair/
├── last_health_report.json
├── last_repair_report.json
├── pending_repair_plan.json       # 仅排队/执行期间存在
├── integrity_state.json           # 最近一次深度完整性检查时间
├── repair_worker.ps1              # 打包版运行时复制到安装目录外
├── external-repair.log
├── known_good/                    # 已验证的离线恢复备份（可用时）
├── backups/<timestamp>/
└── logs/repair-<timestamp>.log
```

源码发布包含：

```text
src/arenyxa/resources/
├── repair_manifest.json
├── repair_seed.zip
└── repair/repair_worker.ps1
```

Windows PyInstaller one-folder 发布在构建后包含：

```text
dist/Arenyxa/repair/
├── install_manifest.json
└── recovery_payload.zip
```

`scripts/build_source_repair_seed.py` 生成源码离线修复种子；`scripts/build_repair_payload.py` 在 PyInstaller 构建结束后为当前 one-folder 安装目录生成完整离线恢复包与文件清单。
