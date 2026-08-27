# Arenyxa V6.0 软件需求规格说明（SRS）

## 1. 文档控制

- 唯一产品需求基线：`Arenyxa_超级项目规划_01-09卷_V6.0_整合版.pdf`
- 基线页数：2,202 页
- 基线 SHA-256：`E63A39BCD714457F3B6F9BC668B87B6880FE98C8FF018E4E5085A41723634143`
- 冲突优先级：用户最新明确要求 > 第 09 卷 V6.0 变更 > 第 01 卷产品基线 > 第 02-08 卷工程细化 > 历史截图/草案
- 实现基线：Modern = Python 3.11-3.13 + PySide6；Legacy Enterprise = Windows 7 SP1 x64 + Python 3.8.x + PySide2；共享 SQLite/FTS、Domain/Application/Infrastructure 核心，通过 PlatformCapabilities/Qt Compatibility Facade 隔离系统差异。

## 2. 产品定位与边界

Arenyxa 是永久免费的开源、本地优先的桌面 Web 数据采集、浏览器自动化、API 与网络抓包分析、数据工程、本地搜索、调度与分布式执行、自托管服务器、开发者扩展和 Liquid Glass 高级动态桌面体验平台。

核心约束：

- 核心功能离线可用；只有用户主动发起的抓取、连接测试、市场访问或服务绑定可以外联。
- 用户决定数据、缓存、日志、导出和项目存放位置。
- Task 是可编辑定义；Run 是带配置快照的事实。修改 Task 不改变历史 Run 的含义。
- Browser 层可见明文和 System Packet 层可见 TLS 密文必须明确区分，系统抓包不宣称自动解密 HTTPS。
- 仅服务于用户有权分析的站点和系统；不提供凭证窃取、会话劫持、TLS 绕过或漏洞利用流程。
- Liquid Glass/Motion 是增强渲染层；关闭透明、动画、折射、GPU 增强后全部业务能力仍可用。

## 3. 基础功能需求注册表

| 域 | 需求 ID | 必须提供的用户结果 |
|---|---|---|
| 应用生命周期 | FR-APP-001..008 | 首次初始化、窗口恢复、单实例、安全关闭、崩溃恢复、构建信息、状态栏、命令入口 |
| 任务管理 | FR-TASK-001..010 | 创建、自动保护、复制、归档、软删除、标签、搜索、验证、导入、导出 |
| 请求配置 | FR-REQ-001..012 | 单/批量 URL、方法、Query、Header、Cookie、Body、超时、重试、限速、UA、代理、TLS |
| 获取后端 | FR-FETCH-001..006 | 静态 HTTP、响应上限、重定向、编码、Playwright 浏览器后端、robots 提示/缓存 |
| 解析系统 | FR-PARSE-001..006 | Content-Type 路由、HTML DOM、JSON、XML、链接发现、解析样本定位 |
| 字段抽取 | FR-FIELD-001..007 | FieldSpec、CSS、XPath、类型转换、必填/默认、多值、命中/空值/失败统计 |
| 清洗质量 | FR-CLEAN-001..006 | 有序流水线、空白规范化、正则、映射、记录去重、质量标记 |
| 预览 | FR-PREV-001..003 | 测试连接、PreviewRun 不写正式表、单字段测试 |
| 数据管理 | FR-DATA-001..005 | Run 关联存储、十万级分页、数据库筛选排序、来源追踪、按范围清理 |
| 导出 | FR-EXP-001..005 | CSV、JSON/JSONL、XLSX、进度/取消、导出历史 |
| 运行队列 | FR-RUN-001..008 | Run 实例、状态机、分阶段进度、取消、暂停恢复、重跑、并发控制、FIFO/优先级 |
| 自动化 | FR-AUTO-001..004 | 每日/每周/间隔、启停、失败策略、明确时区 |
| 搜索 | FR-SEARCH-001..004 | 本地全文/字段搜索、任务/运行搜索、最近查询、索引状态 |
| 可观察性 | FR-OBS-001..005 | 结构化日志、轮转、稳定错误码、Run 摘要、脱敏诊断摘要 |
| 主题 | FR-THEME-001..003 | 六套视觉预设、无独立浅深开关、切换不丢业务状态 |
| 设置/备份 | FR-SET-001..002, FR-BACKUP-001..002 | 设置中心、存储路径、版本化备份、校验与事务恢复 |
| 插件/安全 | FR-PLUG-001..002, FR-SEC-001..003 | Manifest 发现、显式启用、统一脱敏、loopback 默认、安全脚本提示 |

## 4. V6.0 新增 42 项正式能力

### 4.1 Network Capture（FR-V6-071..079）

| ID | 能力 | 验收结果 |
|---|---|---|
| FR-V6-071 | Arenyxa Capture Suite | 统一会话状态机、来源、过滤、存储、Dropped、权限和跨模块跳转 |
| FR-V6-072 | Browser Network Capture 2.0 | 受控浏览器记录 HTTP(S)、Fetch/XHR、GraphQL、Header/Cookie/Payload/Response/Timing/Initiator，并关联 DOM/HAR |
| FR-V6-073 | Process Network Monitor | Process → Endpoint → Protocol → Traffic 实时/快照视图，可按 PID/IP/端口/状态定位 |
| FR-V6-074 | Traffic Timeline & Waterfall | DNS/Connect/TLS/Send/TTFB/Download/Redirect 时间段可视化与慢请求定位 |
| FR-V6-075 | Request Replay Studio | 从不可变记录创建 ReplayDraft，编辑后重放；副作用方法显式确认；结构化比较 |
| FR-V6-076 | API Reverse Engineering & API Map | 确定性识别 REST/GraphQL、路径参数、分页/游标和实体关系，结果可人工审阅 |
| FR-V6-077 | TLS Inspector | TLS 版本、Cipher、证书主体/颁发者/有效期/SAN/SNI 与握手时间；不绕过加密 |
| FR-V6-078 | DNS Analyzer | A/AAAA/CNAME/MX/TXT/NS、解析耗时、错误和连接关联 |
| FR-V6-079 | Advanced HAR Analytics | 导入、会话统计、慢/失败/重定向/缓存/第三方域/P50/P95 和结构化对比 |

统一状态机：`IDLE → PREPARING → CAPTURING ↔ PAUSED → FINALIZING → COMPLETED | FAILED | CANCELLED`。高流量采用有界队列、批次刷新、分块落盘；无法跟上时显式增加 Dropped，不静默丢失。

### 4.2 Advanced Platform（FR-V6-080..087）

| ID | 能力 | 验收结果 |
|---|---|---|
| FR-V6-080 | Smart Execution Planner | 按 Content-Type、DOM/JS、XHR/API、历史成功率和规模确定性推荐 HTTP/API/Browser/Distributed；给出原因与人工覆盖 |
| FR-V6-081 | Website Intelligence Map | 页面、路由、API、Bundle、Cookie、第三方、CDN、实体与依赖的统一图模型 |
| FR-V6-082 | Data Version Control | DatasetRevision、记录/字段/Schema Diff、标签、历史查询、非破坏回滚 |
| FR-V6-083 | Universal Database Adapter | SQLite 与可选 SQLAlchemy 数据库，声明事务/批写/Upsert/Schema/Query/Streaming 能力 |
| FR-V6-084 | Data Visualization Studio | Line/Bar/Pie/Heatmap/Timeline/Map，绑定 Run/字段，保存资产并导出 PNG |
| FR-V6-085 | Web Compatibility Tester | HTML 结构、视口、语言、重复 ID、基础可访问性与可重复报告 |
| FR-V6-086 | Website Performance Profiler | 请求量、体积、Host/MIME、失败、P50/P95 和慢请求列表 |
| FR-V6-087 | Security Analysis Center | 被动检查 HTTPS、HSTS/CSP/CORS/Cookie/Security Header，输出证据和修复建议，不执行攻击 |

### 4.3 Runtime & Ecosystem（FR-V6-088..096）

| ID | 能力 | 验收结果 |
|---|---|---|
| FR-V6-088 | Portable Project Format `.arenyxa` | ZIP 容器、manifest、版本、哈希、Workflow/Selectors/Schema/Tests/Schedule/Visualization；Secrets 默认排除；防路径穿越 |
| FR-V6-089 | Headless Server Mode | 复用同一 Task/Run/SQLite/Plugin Contract；REST、健康检查、loopback 默认、Docker 支持 |
| FR-V6-090 | Multi-User Workspace | Admin/Developer/Viewer 最小权限，项目/任务/数据/Secret/插件/日志/系统操作可审计 |
| FR-V6-091 | Workflow Marketplace | 可选 HTTPS 目录、权限/依赖/版本预览、SHA-256 校验、安装后形成可编辑副本 |
| FR-V6-092 | Hardened Developer Terminal & Packet Console | Arenyxa/Direct/PowerShell/CMD/Python 模式；实时输出、停止、cwd/env/history、只读 SQL、标准输入、超时/输出边界；外部命令需 Developer Mode 和逐次确认 |
| FR-V6-093 | Visual Data Pipeline 2.0 | Source/Filter/Map/Validate/Sink、失败端口、取消与有界数据语义 |
| FR-V6-094 | Automated Regression Lab | DOM Hash、Selector 命中、API Schema、记录量、P95 阈值比较 |
| FR-V6-095 | Browser Profile Manager | 隔离 Profile、UA/语言/代理/时区、SecretRef；会话秘密不随项目导出 |
| FR-V6-096 | Extension Runtime Sandbox | Network/Storage/Browser/Clipboard/Process/Database 权限，隔离进程、超时、输出与 Windows Job 内存预算 |

### 4.4 Liquid Glass & Motion（FR-V6-097..112）

| ID | 能力 | 验收结果 |
|---|---|---|
| FR-V6-097 | Liquid Glass Design System | Blur、半透明 Tint、饱和度语义、内外边缘高光、柔和阴影、景深和状态色 |
| FR-V6-098 | Material & Layer Engine | Surface/Glass/Elevated/Overlay/Solid Fallback 与明确 Z-Depth；页面仅引用 Token |
| FR-V6-099 | Backdrop Sampling & Adaptive Tint | 根据亮度/对比度调整 Tint/文本/边缘；复杂背景提高遮罩保证可读性 |
| FR-V6-100 | Refraction & Specular Highlight | 克制的边缘折射和指针高光；低性能/远程桌面/Reduce Motion 可关闭 |
| FR-V6-101 | Spring Motion System | 可中断弹簧积分器，以 response/damping/mass 语义表达，不使用线性动画 |
| FR-V6-102 | Shared Element & Morph Transition | Dashboard→Task、Request→Replay、Map→Detail 保持位置/尺寸/圆角/材质连续性 |
| FR-V6-103 | Edge Flow & Light Trail | 仅在启动/完成/严重错误/数据变化短时传播，非线性衰减，不持续炫光 |
| FR-V6-104 | Live Data Motion | Network/Runner/Pipeline 以受控动态表达吞吐、压力和阶段，业务数据仍用数值/状态呈现 |
| FR-V6-105 | Advanced Panel Physics | 侧栏/Inspector 拖拽、吸附、速度阈值、弹性边界及键盘等价入口 |
| FR-V6-106 | Motion Orchestrator | Enter/Exit/Expand/Collapse/Move/Emphasize/Success/Warning/Error/LiveData 集中编排 |
| FR-V6-107 | High Refresh & Frame Pacing | 60/90/120Hz 真实时间驱动，PreciseTimer 与刷新率适配，动画不阻塞业务 |
| FR-V6-108 | GPU Compositor & Adaptive Quality | Windows DWM/Mica 请求、Qt 合成层、P95 帧预算监测和 high/balanced/efficiency 降级 |
| FR-V6-109 | Microinteraction System | Hover/Pressed/Focus/Selected/Loading/Success/Warning/Error 统一语义 |
| FR-V6-110 | Motion Accessibility & Reduce Motion | 关闭大位移/折射/粒子/视差，改用短淡入/颜色/边框；功能和状态反馈保留 |
| FR-V6-111 | Motion & Glass Personalization | 材质、透明、Blur、动态强度、边缘流光、Live Motion、性能模式可保存 |
| FR-V6-112 | Animation & Compositor Profiler | 刷新率、预算、P50/P95、Dropped Frames、Quality 状态可观测 |

## 5. UI 信息架构

主窗口必须保持：左侧导航栏 + 顶部工具栏 + 中央工作区 + 可折叠右侧上下文检查器 + 底部状态栏。六套主题共享完全相同的 `MainWindow`、页面对象和状态；主题切换不得重建业务对象、清空表单或移动命令。

主题映射：

1. Clean Light / Layout Baseline Light
2. Modern Dark / Dark Operations
3. Professional Graphite
4. Terminal Green
5. Blue Productivity
6. Aurora Glass / Aurora Visual

## 6. 数据与安全

- 所有持久化核心对象携带 `schema_version`；升级按 migration 链执行。
- 事实关系使用稳定 ID，不以显示名称关联。
- SQLite 启用 WAL、foreign_keys、busy_timeout、显式事务和批量写入。
- 原始 Packet 使用 pcapng ring buffer；元数据/索引批量落库；崩溃恢复以已提交 Chunk 为边界。
- `Redactor` 统一处理 Authorization、Cookie、Token、Password、Secret 和 Body 策略。
- Server 默认 `127.0.0.1/::1`；非 loopback 必须显式 `--allow-lan`，并应由 TLS 反向代理保护。
- Replay 对 POST/PUT/PATCH/DELETE 强制副作用确认；捕获原记录不可变。

## 7. 非功能要求与发布门禁

- GUI：长任务期间可导航、滚动、打开日志和取消；高频进度/网络事件 200ms 批次节流。
- 大数据：结果表采用分页模型；网络表最多 materialize 20,000 个可见事件，完整数据在 SQLite/Chunk 中。
- 帧预算：60Hz 16.7ms、120Hz 8.3ms；连续超预算进入 balanced/efficiency，停止装饰性连续动画。
- 高 DPI：100%-200%，布局使用 Qt Layout/Token，不依赖单一 1920×1080 坐标。
- 国际化：简中、繁中、英、法、俄、德、日、韩、阿拉伯、拉丁；阿拉伯语启用 RTL，代码/时间语义不镜像。
- 可访问性：键盘导航、焦点、Tooltip/AccessibleName、非纯颜色状态、Reduce Motion 和高对比回退。
- Windows：x64；PyInstaller portable build；Inno Setup Installer、快捷方式、文件关联和卸载程序。
- 测试：单元、契约、集成、迁移、网络 mock、插件安全、Qt offscreen、视觉截图、安装启动和数据库完整性。

