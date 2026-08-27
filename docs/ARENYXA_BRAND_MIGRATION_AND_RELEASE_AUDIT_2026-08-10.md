# Arenyxa v6.6 本地稳定源码迁移与开发者验证审计

日期：2026-08-10

## 1. 唯一基线

本轮最终交付以用户本地稳定发布阶段的 `Arenyxa_V6.6_Stable_Release_Source.zip` 为唯一源码基线，不使用后续 GitHub Ready 包作为交付基线。

迁移目标是把公开产品身份切换到 Arenyxa v6.6，同时保留经过稳定性审查的内部实现和必要的旧版本兼容边界。`src/arenyxa/` 是新的公开入口；`src/arenyxa/` 暂时保留为 v6.6 内部兼容实现命名空间，避免插件、旧项目、恢复包和既有脚本因一次品牌重命名发生破坏性断裂。

## 2. 新增开发者验证能力

内置 Developer Terminal 新增两个受保护命令：

- `test-all`：在隔离临时目录和 `127.0.0.1` 回环服务中执行完整本地功能验证。
- `stress-test quick|standard|extreme`：逐级提高并发，记录吞吐、P95 延迟、Python 峰值内存、错误数、最高已观察稳定 worker 数与第一个不稳定 worker 数。

`test-all` 与 `stress-test` 均要求：

1. 在设置 → 高级设置中启用 Developer Mode；
2. 阅读并勾选开发者风险协议；
3. 阅读并勾选测试免责协议；
4. 当前协议版本与接受时间必须有效。

旧设置即使残留 `developer_mode=true`，若没有当前协议版本和接受时间，上述两个命令仍保持锁定。

## 3. 安全边界

完整功能验证不会主动访问公网目标，不修改正式项目数据。除当前正式数据库的只读 `ping/quick_check` 外，数据库写入、Capture、导出、Run pipeline、原子文件写入均使用临时目录或回环服务。

压力测试采用有界模型，不以耗尽系统内存、填满磁盘或使操作系统失去响应为目标。`extreme` 的内置安全上限为 64 workers；达到上限仍未发现异常时，结果必须表述为“安全上限内未观察到崩溃”，不得伪造实际崩溃点。

## 4. `test-all` 实际覆盖

当前实现包含 14 个实际执行项，并额外执行高级功能 wiring 审计：

1. 高级能力 wiring；
2. 当前数据库 ping/quick_check；
3. 原子文件写入；
4. HTML/JSON/XML 解析与字段提取；
5. Selector 分析与恢复；
6. Workflow Engine；
7. Scheduler interval；
8. 隔离 SQLite Task roundtrip；
9. Capture Event 持久化；
10. CSV/JSON/XLSX 导出；
11. 127.0.0.1 HTTP Client；
12. 127.0.0.1 RunOrchestrator 完整采集链；
13. Developer Terminal 项目根沙箱；
14. Data Quality / Workflow Variables / Templates。

高级能力 wiring 当前覆盖 30 个显式 runtime contract。需要真实浏览器、系统抓包驱动、远程 Worker 或第三方数据库的能力只检查本地实现是否正确 wiring，不在一键命令里擅自连接外部环境。

## 5. 本轮实际发现并修复的问题

本轮回归过程中实际发现并处理了以下问题：

1. 双协议对话框使用 `QDialogButtonBox.StandardButton.Ok`，而 Win7/PySide2 Qt 兼容包装原先没有导出该枚举；已补兼容映射并增加回归锁定。
2. JSON 字段验证最初给 `FieldSpec` 传入不存在的 selector 类型；已改为合法字段定义并显式验证 integer coercion。
3. 压力测试原子写路径在首轮实现中没有预创建父目录；已在每个压力级别开始前建立隔离目录。
4. 本地稳定基线的 Repair Seed/Manifest 仍是品牌迁移前版本，且未覆盖新的 `src/arenyxa/` facade；已重新生成并把新开发者验证模块纳入恢复保护。
5. 本地稳定基线的 `build.ps1` 仍指向旧 PyInstaller spec、旧 dist 路径，并只探测 Inno Setup 6；已改为 Arenyxa spec/dist，并兼容 Inno Setup 6/7。
6. 旧测试和文档仍要求已经移除的可选本地助手界面；已移除对应实现、文案和过时契约，防止发布包继续携带不需要的模型/服务字段。
7. 本地 Stable 的 Source Manifest 在代码变更后自然失效；最终源码冻结后重新生成，而不是修改测试绕过哈希检查。

## 6. 指定字段清理

本轮删除了旧的可选本地助手实现、UI 页签、相关测试契约、文档说明和模型端点示例。最终交付前会对源码、测试、脚本、配置、说明文档和 Repair Seed 内部文本再次执行大小写无关的禁用关键字扫描；命中数必须为 0。

Web Intelligence、Autopilot、Selector Recovery 等现有确定性功能保留，它们的核心执行不依赖外部模型服务。

## 7. 压力验证观察值

当前审查环境实际执行结果：

- `quick`：1 → 2 → 4 workers，0 error；
- `standard`：1 → 2 → 4 → 8 → 12 workers，0 error；
- `extreme`：1 → 2 → 4 → 8 → 12 → 16 → 24 → 32 → 48 → 64 workers，每级 600 次混合操作，0 error；
- 在 64 workers 安全上限内没有观察到崩溃；高并发阶段 P95 延迟明显上升，因此该命令用于观察稳定性和退化曲线，而不是鼓励普通用户长期使用极端并发。

这些数值只描述本次审查机，不代表其他 CPU、磁盘、杀毒软件、驱动或 Windows 版本的固定极限。

## 8. Repair / Provenance

最终 Repair Seed 重新从当前源码生成，产品身份为 Arenyxa，同时覆盖 `src/arenyxa/` 公共 facade 和 `src/arenyxa/` 内部兼容实现。生成后必须通过：

- 外部 Seed SHA-256 与 Manifest 对账；
- ZIP CRC；
- 内部 `MANIFEST.json` 与外部 manifest 文件表一致；
- 每个受保护文件当前 SHA-256 与表中值一致；
- Repair Seed 内文本禁用关键字扫描为 0。

`SOURCE_MANIFEST.sha256` 必须在全部源码、测试和文档冻结后最后生成。

## 9. Windows 发布边界

本轮审查环境不是原生 Windows，因此不能把静态打包契约等同于真实 EXE/Installer 认证。正式二进制发布前仍必须在 Windows 原生环境执行：

1. `scripts\test.ps1`；
2. `scripts\build.ps1`；
3. `dist\Arenyxa\Arenyxa.exe` 启动/退出/重启；
4. `Arenyxa_V6.6_Setup_x64.exe` 首装、覆盖升级、卸载；
5. Windows 7 SP1 x64 Legacy 独立构建和 PySide2 GUI 冒烟。

Linux 审查中的 Qt skip 不得描述成 Windows GUI 已验证。
## 10. 最终完整回归

源码冻结阶段再次以单一 pytest 进程执行完整收集集，最终结果为 **377 passed、6 skipped、0 failed，40.39 秒**。测试进程自然退出，退出后没有残留 pytest/Arenyxa 子进程。6 个 skip 均来自当前环境没有受支持 Qt binding 的 GUI/visual smoke。

