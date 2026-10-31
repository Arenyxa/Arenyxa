# Arenyxa v6.8 Stable 最终性能、稳定性与兼容性冻结

日期：2026-08-11

## 交付边界

本次继续使用 `6.8 / 6.8.0` 正式版身份，不删减页面、服务、数据模型、插件接口或历史兼容入口。
Repair 单终端、Capture 结束态、85%-160% UI 缩放、自适应请求并发、X 风格中心 Logo 连续启动
交接均保留。Git 历史和 Inno Setup 安装包不在本次源码交付范围内。

## 性能修复

- HTTP 请求不再逐次创建默认 TLS 上下文。验证/不验证证书的上下文按进程惰性缓存，opener 仍按请求
  隔离，兼顾线程安全与代理行为。隔离测量避免了每次请求约 `18.5 ms` 的上下文构造成本。
- SQLite 新连接的会话级 PRAGMA 合并为一次初始化；`timeout=30` 继续提供相同 busy handler，
  `foreign_keys`、`synchronous=NORMAL`、WAL checkpoint、cache 和 memory temp-store 合同不变。
- `save_task()` 只构造一次规范 JSON，并直接对同一字节序列计算 SHA-256；5000 请求任务的隔离测量
  约为原路径的 `1.93x`。
- `save_run()` 对已有运行采用窄 UPDATE，只有首次创建才序列化不可变任务快照；100 次 5000 请求
  进度保存由约 `3.322 s` 降至 `1.627 s`，约 `2.04x`。
- Runner 将受主机并发/速率限制的待办项惰性分桶并轮转补位。10 万同主机积压由反复 O(N)
  扫描改为一次分类和稳态 O(1) 等待；旧路径持续占用约 `76.7%` 单核，新路径分类后采样接近
  `0%`，取消进入终态约 `14 ms`。
- 自适应控制的本地处理计时现包含 `ResultRecord` 规范化与哈希；解析后尽早释放响应字节和文档树，
  大响应并发下不会因为漏计 CPU 成本而错误扩容。
- 压力报告明确标记为 `local-persistence-mixed-v2`，并拒绝在外部 `tracemalloc` 已开启时给出受污染
  的计时结果。该通道代表 SQLite/FTS、原子文件、JSON 和选择器混合负载，不冒充公网 HTTP 分数。

旧版与本版交替 Standard A/B 中，新版 4-worker 平均吞吐提高约 `4.6%`，8-worker 提高约
`11.6%`；4/8/12-worker P95 分别下降约 `11.5% / 17.0% / 23.8%`。最终冻结连续执行三次
Standard 与一次 Extreme，共 9,600 次计时操作，全部零错误：Standard 的 4-worker 吞吐/P95
中位数为 `495.87 ops/s / 30.06 ms`，三轮均推荐 4 workers；Extreme 验证到 64 workers 仍未
出现错误或不稳定级别，并继续推荐 4 workers。

## 稳定性修复

- Windows Repair 进程探测不再调用 `os.kill(pid, 0)`；该调用在 Windows 并非 POSIX 无害探测，
  可终止被检查进程。现在使用具有明确 HANDLE 签名的 WinAPI，拒绝访问/未知状态按保守存活处理。
- Capture 的 prepare、start、pause/resume 和 stop 边界进一步事务化：无效过滤器或持久化失败不会
  毒化控制器；线程启动失败可复用；暂停/恢复写库失败会回滚适配器与内存状态。
- Capture 回调严格绑定 session，并在入队和过滤器失败提交前二次校验。旧适配器迟到事件、过滤期间
  换会话，以及 stop 与过滤失败最终提交的 TOCTOU 均被同一状态锁隔离，不会污染下一会话或把
  `COMPLETED` 反写为 `FAILED`。
- Runner pause/resume 的控制 I/O 独立串行，避免内存为 RUNNING、数据库却被旧 pause 写回 PAUSED；
  尚未开始的 queued Future 在取消时可立即进入取消路径。
- Workflow shutdown token 从公开入口、首次仓储副作用之前登记；shutdown 不会在 revision/execution
  仍可能写库时提前返回。

## 兼容性与启动连续性

- MainWindow 最小尺寸按实际启动屏幕的逻辑可用矩形收缩，1920×1080@200%、960×540、800×600
  等小逻辑桌面不会被固定 1120×720 再次撑出屏幕，也不会破坏 Splash 与主窗的几何连续性。
- Splash Logo 按设备像素比生成物理像素并写入 pixmap DPR；高 DPI 下保持清晰、中心一致。
- Windows 的 `SPI_GETCLIENTAREAANIMATION` 系统辅助功能偏好与用户 Reduce Motion 设置做运行时 OR；
  系统偏好不会被写回用户配置，也不能被后续质量档位绕过。
- Windows 10/11 默认继续使用现代 Python/Qt 通道；显式 `legacy-enterprise` 可在现代 Windows 上验证
  Python 3.8/PySide2 企业环境。旧版启动入口保持兼容。
- 文本子进程对本地代码页异常字节采用 replacement 解码，避免输出解码崩溃；一键启动器会实际导入
  Qt、lxml、cssselect、dnspython、openpyxl、cryptography 和 tzdata，二进制损坏或缺依赖会触发恢复。
- 中心 Logo、干净背景、连续放大、同窗圆形遮罩揭开以及 portrait/ultrawide/多屏/DPI/Reduce Motion
  路径保持完整，不引入第二个可见主窗口。

## 验证矩阵

本轮至少覆盖以下独立维度：

1. 完整 pytest 单元/集成/契约回归；
2. Python compileall；
3. release-blocking Ruff；
4. Python 3.8 grammar；
5. Windows Repair 子进程存活与未知句柄；
6. Capture 生命周期、迟到回调、过滤器/stop 交错和持久化回滚；
7. Runner host 分桶公平性、许可补位、大积压取消与 pause/resume 顺序；
8. Workflow shutdown 与仓储副作用排序；
9. SQLite task/run 快照、状态保护和 PRAGMA 合同；
10. TLS 上下文缓存与并发复用；
11. 960×540、800×600、200% DPI 与多屏启动几何；
12. 系统/用户 Reduce Motion 与 X 风格遮罩终点；
13. Modern/Legacy runtime 选择与 Python 3.8/PySide2 通道；
14. PowerShell 一键启动脚本语法和核心依赖实际加载；
15. 三次 Standard 及一次 Extreme 压力冻结；
16. Repair Seed 内容、CRC 与 SHA-256；
17. Source Manifest 全文件哈希；
18. 干净源码目录与 ZIP 的 CRC、解压后逐文件一致性。

完整性重建后的最终全量回归为 `474 passed / 1 skipped / 0 failed`；唯一跳过项是在 Windows 上
不可用的 POSIX `/proc` 文件描述符统计。Repair Seed 独立完成 CRC/清单/内容校验，兼容性冻结另有
85 项 Windows/DPI/Reduced Motion/Legacy/Qt 专项全部通过，92 个源码文件通过 Python 3.8 grammar。

完整性文件在所有源码、测试和本文档冻结后重新生成。交付目录不包含 `.venv`、缓存、`*.egg-info`、
构建目录、Git 元数据或 Inno Setup 输出。
