# Arenyxa V6.0 深度代码审阅与 About 信息中心优化记录

- 审阅日期：2026-08-08
- 审阅基线：`Arenyxa_V6.0_Provenance_AntiTamper_Hardened.zip`
- 范围：启动生命周期、调度、HTTP、抓包、SQLite、项目包、发行完整性、Repair Center、Qt 线程边界、数据/网络页面、国际化，以及 About 页面。
- 原则：修复真实缺陷优先，不借“优化”重写已确认 Dashboard、主题、终端、抓包或业务信息架构。

## 1. 本轮确认并修复的缺陷

### 1.1 启动与单实例

1. **第二实例曾在取得单实例锁之前执行 bootstrap。** 这会短暂创建第二个 Scheduler，并可能留下错误的 `crash.marker`。现改为 Qt Application 创建后立即取得单实例锁，第二实例仅发送 IPC 激活/项目路径并退出。
2. **启动最前端 locale 读取对合法但错误结构的 JSON 不够稳健。** `settings.json=[]` 等情况现在安全回退，不会在 Repair Center 接管前抛 `AttributeError`。
3. **ApplicationContext shutdown 改为幂等、逐项 best-effort。** Scheduler、Capture、Runner、Settings 任一清理失败不再阻断后续资源释放。

### 1.2 自动化调度

4. `ScheduleRule` 增加 kind、interval、hour/minute、weekday、timezone 的完整边界校验；无效的持久化 Schedule 会被隔离而不是拖垮启动。
5. interval 按 UTC elapsed time 计算，避免 DST 导致“每 N 分钟”被人为缩短/拉长。
6. 同一 Schedule 禁止重叠执行，避免慢任务与短周期组合产生无限线程堆积。
7. Scheduler 回调异常与 reschedule 持久化异常现在只影响对应任务，不终止主调度循环。

### 1.3 HTTP 与解析

8. 修复 `RetryPolicy.retry_statuses` 之前定义但未真正生效的问题；429/5xx 等配置状态现在按策略重试，耗尽后返回稳定错误码。
9. gzip 改为流式、解压后大小受限，避免“小压缩响应异常膨胀”造成内存压力。
10. Content-Type / Content-Encoding 改为大小写不敏感读取。
11. RequestSpec 校验对损坏 JSON 中的错误类型、NaN/Infinity、非法 timeout/retry/header 等保持可诊断，不再因 Python TypeError 直接中断。
12. 缺少 `cssselect` 时明确报告 `EXTRACT_DEPENDENCY_MISSING`，不再误导为 CSS selector 语法错误。

### 1.4 抓包与数据一致性

13. Capture Writer 的 SQLite 写入失败不再静默退出后仍把 Session 标记为 Completed；现在 Session 会进入 Failed，并返回 `CAPTURE_STORAGE_FAILED`/`CAPTURE_FINALIZATION_FAILED`。
14. Adapter stop、Writer join、chunk metadata、最终 Session save 被拆成可追踪的失败边界；listener 异常不能再杀死 persistence writer。
15. 事件行已提交但 Session 摘要写入失败时，内存计数仍保留已提交事实，最终保存有机会修复摘要，不会把真实已落库事件“回滚成不存在”。

### 1.5 SQLite 与损坏对象容错

16. 损坏的 `schedule.rule_json` 现在按行隔离。
17. 损坏的 Task definition 不再让整个 Task/Dashboard 列表无法打开；列表会跳过该对象并记录日志，直接读取该 Task 时返回稳定 `TASK_DEFINITION_CORRUPT`。
18. Task 反序列化不再原地 `pop()` 输入 JSON 的嵌套对象，减少隐式数据变异风险。

### 1.6 `.arenyxa` 项目包

19. Reject 未在 manifest 声明的额外文件、重复 ZIP 条目、路径穿越、Unix symlink、错误 manifest 根类型/未知字段/非法哈希。
20. 大文件哈希改为流式读取，避免校验阶段把超大 entry 一次性载入内存。
21. pack 阶段也执行与 validate 一致的数量/总大小边界，防止 Arenyxa 自己创建之后自己拒绝的项目包。
22. **重复导出到项目树内部时，旧 `.arenyxa` 目标文件不会被递归打进新项目包。**
23. pack 改为临时文件构建 + 自验证 + 原子替换；写盘失败不会覆盖最后一个已知可用的项目包。
24. unpack 改为同磁盘 staging + 完整提取 + 原子提交；拒绝非空目标，磁盘满/权限错误不会留下“半个项目”供后续误用。

### 1.7 Qt 主线程与大数据 UI

25. Runner progress 通过 Qt Signal 跨线程回主线程，不再依赖 worker 线程中的 `QTimer.singleShot`。
26. Historical Network Session（最高约 20k events）、Visualization（约 10k records）、Dataset Revision compare/show 和 Logs tail 读取移到 background job。
27. Network 页面增加 generation token，旧后台请求完成后不会覆盖用户已经切换到的新 Session；历史 Session 视图也不会再混入其他实时 Capture 的事件。
28. Logs 使用 bounded `deque(maxlen=3000)`，不再先 `readlines()` 把整个大型日志读进内存。
29. 打开数据目录使用 `QDesktopServices`，不再依赖仅 Windows 可用的 `os.startfile`。

### 1.8 发行完整性与 Repair Center

30. Deep provenance 校验除了 manifest 内已声明文件外，进一步检测签名目录外出现的 `.exe/.dll/.pyd/.py/.pyc/.pth/.so/.dylib` 等额外可加载代码。
31. release manifest 与 attestation 增加大小/结构/哈希/路径规范校验，避免“可信文件本身被畸形输入拖垮验证器”。
32. Startup 定期深检现在真正执行 signed file/recovery/unexpected-loadable 校验；源码模式仍保持自由修改，不把开发者改代码当作必须回滚的篡改。
33. 本轮源码变化后重新生成 source `repair_seed.zip` 与 `repair_manifest.json`，Repair Center 不会把新代码恢复成旧基线。

## 2. About 页面重新定位

旧 About 主要是版本文字。本轮把它改为 **Release / Runtime / Privacy / License / Health 信息中心**，并避免做成开发者 dump。

包含：

- Arenyxa Logo、版本、Python/PySide6 版本与产品定位。
- 发行身份：Development / Verified Official / Verified Community / Modified / Unverified / Invalid。
- **快速身份检查**仅验证 release attestation，保证打开 About 不被大量文件哈希阻塞。
- **“深度验证安装”后台任务**：逐文件验证 signed manifest、检测额外可加载代码、验证 recovery payload，并运行 SQLite `PRAGMA integrity_check`。
- 深度结果完成后立即刷新 About 上方的真实发行身份，避免“签名有效但文件已改”仍显示过于乐观的状态。
- Runtime / Local Data：OS、Architecture、Python、PySide6、Application root、Data root、Database、Logs。
- Local-first / Privacy：明确“本地优先 ≠ 永不联网”；目标网站抓取、用户主动启用的 Server/Marketplace/Network 功能按用途访问网络。
- GPL-3.0-or-later 与发行边界：明确签名是 provenance/integrity，不是 DRM、联网激活、硬件绑定，也不禁止 GPL 允许的合法修改或商业分发。
- Core Capabilities 摘要与“复制构建信息”。
- 使用 ScrollArea，提升窄窗口、125%–200% DPI 和长文本环境下的可达性。
- About 新增关键文字进入 i18n fallback/native catalog；技术路径、SHA-256、版本信息在 RTL 下仍按 LTR 语义展示。

## 3. 验证结果

本轮最终回归以“功能契约 + 安全边界 + 解析/编译”为主：

- Focused resilience/security/provenance/project/repair tests：通过。
- 非 GUI 测试：除当前审阅容器未安装 `cssselect` 导致的 1 项依赖环境失败外，其余通过；`requirements.txt` 与 `pyproject.toml` 已声明 `cssselect`。
- Python `compileall`：通过。
- AST parse：全部 Python 文件无语法错误。
- 当前容器未安装 PySide6，因此不能在此环境伪称已经完成真实 Qt 窗口像素级/交互式 smoke test。
- 当前容器不是完整 Windows 发行环境，因此 PowerShell Repair Worker、tshark/dumpcap、Playwright/浏览器驱动、Inno/PyInstaller 安装包仍需在 Windows CI/本机执行最终 E2E。

## 4. 仍需按真实发行环境验证的风险

没有客户端软件能靠静态审阅证明“绝对没有 bug”。当前剩余主要风险是环境型而非已知代码崩溃：Windows DPI/多显示器、真实网络异常、驱动/抓包权限、杀毒软件文件锁、安装/升级/卸载、极端磁盘满、长时间 24h+ Scheduler/Capture、真实 Qt 事件循环和 GPU/Compositor 表现。这些应进入 Windows Release Gate，而不是用“代码能编译”替代。
