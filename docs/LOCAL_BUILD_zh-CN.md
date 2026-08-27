# Arenyxa V6.6 本地编译与调试教程

## 1. 环境要求

- Windows 10 22H2 或 Windows 11 x64
- Python 3.11、3.12 或 3.13 x64
- PowerShell 5.1 或 PowerShell 7
- 至少 4 GB 可用磁盘空间（安装浏览器运行时需要额外空间）
- 可选：Git、Packet Analysis/Npcap、Playwright Chromium、Inno Setup 6 或 7

不要使用 Python 3.14：当前项目发布基线冻结在 3.11-3.13，以获得稳定的 PySide6/PyInstaller 兼容链。

## 2. 自动建立隔离环境

在源码根目录打开 PowerShell：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\bootstrap.ps1
```

脚本执行以下动作：

1. 按 `py -3.13` → `py -3.12` → `py -3.11` → `python` 的顺序探测受支持的 64 位解释器；若已有 `.venv` 版本/位数不兼容，会先保留为带时间戳的备份再重建。
2. 创建源码目录内 `.venv`，不修改系统 Python。
3. 升级 pip/setuptools/wheel。
4. 以 editable 模式安装 Arenyxa、PySide6、lxml/cssselect、dnspython、openpyxl、Playwright、数据库驱动，以及测试、Server 和 Process Monitor 依赖。
5. 下载经过 Playwright 固定版本管理的 Chromium 运行时。

若只做无浏览器引擎的离线代码审阅，可使用 `./scripts/bootstrap.ps1 -SkipBrowserRuntime` 跳过约 300 MB 的 Chromium 下载；Browser Capture 在安装运行时前会明确报告缺失，不会静默替代。

## 3. 运行桌面程序

```powershell
.\scripts\run.ps1
```

指定隔离数据目录：

```powershell
.\scripts\run.ps1 --data-dir D:\ArenyxaData
```

安全模式：

```powershell
.\scripts\run.ps1 --safe-mode
```

打开新的 `.arenyxa` 项目（旧 `.arenyxa` 仍兼容）：

```powershell
.\scripts\run.ps1 D:\Projects\example.arenyxa
```

默认新应用数据位于 `%LOCALAPPDATA%\Arenyxa`，包括 `arenyxa.db`、`logs`、`cache`、`exports`、`captures`、`projects`、`plugins` 和 `profiles`。优先使用 `ARENYXA_DATA_DIR` 或 `--data-dir` 覆盖；为兼容 v6.6 迁移前部署，`ARENYXA_DATA_DIR` 仍作为后备变量接受。若检测到已有 `%LOCALAPPDATA%\Arenyxa`，程序会继续复用该数据根而不是自动搬移，以降低升级期间的数据丢失风险。

## 4. 外部运行时与适配器

### Browser Network Capture

标准 `bootstrap.ps1` 已完成安装。若曾使用 `-SkipBrowserRuntime`，执行：

```powershell
.\.venv\Scripts\python.exe -m playwright install chromium
```

Browser Profile 数据放在应用数据目录 `profiles`；Cookie/LocalStorage 等敏感会话数据不进入 `.arenyxa` 包；读取旧 `.arenyxa` 包时同样遵循该规则。

### System Packet Capture

1. 安装兼容的 x64 packet-analysis runtime，并确保提供 tshark/dumpcap。
2. 安装向导中启用 Npcap。
3. 确认 `tshark.exe` 和 `dumpcap.exe` 在 PATH，或将 packet-analysis runtime 的可执行文件目录加入 PATH。
4. 在“网络分析”中选择 `System Packet (tshark)`；仅此能力可能由驱动要求更高权限。

Arenyxa 使用 tshark 生成结构化元数据，使用 dumpcap ring buffer 保存 pcapng Chunk。系统抓包看到的 HTTPS 正文仍是密文。

### Universal Database Adapter

标准 `bootstrap.ps1` 已安装 SQLAlchemy、psycopg 与 PyMySQL 适配器。

PostgreSQL 使用 `postgresql+psycopg://...`，MySQL 使用 `mysql+pymysql://...`。凭证应通过 SecretRef/环境注入，不保存到普通日志或项目包。

### Headless Server

```powershell
.\scripts\start-server.ps1
```

默认绑定 `127.0.0.1:8787`。首次会生成随机管理员 token 并显示一次。非 loopback 监听需要 `--allow-lan`；生产环境必须配置 TLS 反向代理、防火墙和独立 token。

Docker：

```powershell
docker compose up --build
```

Compose 仍把宿主机端口绑定到 `127.0.0.1`。

## 5. 调试方法

### PyCharm / VS Code

- Interpreter：`.venv\Scripts\python.exe`
- Module：`arenyxa`
- Working directory：源码根目录
- 环境变量（离屏 UI 测试时）：`QT_QPA_PLATFORM=offscreen`

### 结构化日志

日志文件：`%LOCALAPPDATA%\Arenyxa\logs\arenyxa.jsonl`。每行是 JSON，包含时间、等级、模块、消息、Error Code 和脱敏 Context。可在程序“日志与诊断”页面查看。

### 数据库

SQLite 启用 WAL。不要在程序运行时复制单独的 `.db` 文件做备份；应使用 SQLite backup API/程序备份入口，或同时处理 `-wal/-shm`。完整性检查：

```powershell
.\.venv\Scripts\python.exe -c "from pathlib import Path; from arenyxa.infrastructure.database import SQLiteStore; print(SQLiteStore(Path(r'%LOCALAPPDATA%\Arenyxa\arenyxa.db')).integrity_check())"
```

### Qt 插件问题

设置 `QT_DEBUG_PLUGINS=1` 后从 PowerShell 启动，可检查 platform/imageformats DLL 加载。正式安装包不应依赖开发机 PATH。

## 6. 测试

```powershell
.\scripts\test.ps1
```

测试使用临时目录和本地 mock HTTP，不依赖公网。门禁包括 compileall、Domain/Parser/SQLite/Filter/HAR/Revision/Project/Plugin/Workflow、Qt offscreen smoke、六主题状态保持和图标哈希。

单独运行：

```powershell
$env:QT_QPA_PLATFORM='offscreen'
.\.venv\Scripts\python.exe -m pytest tests\test_ui_smoke.py -vv
```

## 7. 常见问题

- `No module named PySide6`：运行 `scripts\bootstrap.ps1`，确认使用 `.venv`。
- `cssselect does not seem to be installed`：运行 `.\.venv\Scripts\python.exe -m pip install cssselect`。
- Browser Capture 提示依赖缺失：安装 browser extra 并执行 `playwright install chromium`。
- System Capture 提示驱动缺失：安装兼容的 packet-analysis runtime 与 packet-capture driver，或使用 Browser Capture/HAR。
- 主题/插件导致启动失败：使用 `--safe-mode`；应用会保留数据库并关闭增强视觉/插件。
- 窗口在屏幕外：删除应用数据目录中的 `window.ini`，业务数据库不会被删除。
