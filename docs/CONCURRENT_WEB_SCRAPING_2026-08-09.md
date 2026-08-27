# Arenyxa V6.0 — 多线程网页抓取并发专项设计与审查

## 1. 目标

本轮把 Capture Task 从“Run 可以后台执行，但同一个 Task 的多个 URL 主要顺序抓取”升级为受控的两级并发执行模型。目标是提高多 URL 抓取吞吐，同时保持 Arenyxa 的本地优先、可暂停/取消、SQLite 稳定性、低端设备自适应和可诊断性。

本实现不是递归 Spider，也不会自动从页面发现并无限扩展链接。它并行执行 Task 中显式保存的多个 RequestSpec；普通任务编辑器现在支持“一行一个 URL”。

## 2. 并发模型

### 2.1 Run 级并发

`RunOrchestrator.executor` 使用独立 `arenyxa-run` ThreadPoolExecutor。`run_workers` 决定可同时活跃的独立 Run 数量。

### 2.2 Request 级并发

`RunOrchestrator.request_executor` 使用独立 `arenyxa-fetch` ThreadPoolExecutor。`request_workers` 是整个进程共享的 HTTP/Parse/Extract 全局并发预算。

一个 Run 不会把几十万 URL 一次性全部 submit 到 ThreadPoolExecutor 的无界队列。调度器只维持最多 `request_workers` 个 in-flight Future，其余 URL 保存在有界增长特性的 deque 调度源中，从而避免 Future/闭包/Request 对象造成额外内存峰值。

### 2.3 Host 并发上限

每个 Run 自己先应用 `per_host_workers`，进程内再通过共享 `_HostLimiter` 做第二层 Host Gate。多个同时运行的 Task 访问相同 Host 时，总并发仍不会突破配置上限。

Host Gate 使用引用计数；没有等待或占用者后会自动从表中移除，避免大量唯一域名永久增长协调状态。

## 3. 线程安全不变量

请求 Worker 仅执行：

`Fetch -> Parse -> Extract -> ResultRecord`

Worker 不直接修改 Run 计数器，也不直接写 SQLite。所有 Future 结果回到该 Run 的拥有线程后统一归并：

- request/success/failure/retry/completed 计数；
- content_hash 去重；
- ResultRecord 批量落盘；
- Run 状态机与错误码；
- 节流后的 UI progress callback。

这避免多个请求线程争抢同一个 Run 对象，也避免把 SQLite 变成高竞争多写者热点。

## 4. 暂停、恢复与取消

`CancellationToken` 已改为基于 `threading.Event` 的线程安全协作令牌：

- Pause：所有并发请求在 checkpoint 阻塞；
- Resume：统一唤醒；
- Cancel：设置取消位并同时唤醒正在 Pause 的 Worker，确保其能退出；
- Run 结束后的 Pause/Resume/Cancel 不再覆盖 COMPLETED/PARTIAL/FAILED/CANCELLED 等终态。

正在进行的底层阻塞 socket 调用无法被 Python Event 立即强制中断，因此 Cancel 的最迟响应仍受当前单次网络 timeout 约束；这是受控协作取消，而不是不安全地终止线程。

## 5. 部分失败语义

并发模式下，一个 URL 的网络/解析/字段失败不会取消同一 Task 的其他 URL：

- 全部成功：`COMPLETED`
- 部分成功、部分失败：`PARTIAL` + `RUN_PARTIAL_FAILURE`
- 全部失败：`FAILED`
- 用户取消：`CANCELLED`

日志保留具体 request_index 和底层 error_code，方便定位单个 URL。

## 6. 数据库与背压

结果按照 `result_write_batch_size` 由 Run 线程批量写入 SQLite。低端设备使用更大的批次、较低请求并发和较低进度刷新频率，从而减少事务频率和 GUI Event Loop 压力。

如果结果写入或 Run 协调线程发生异常且仍有 in-flight Worker，最终清理会自动 cancel 共享 token，并尝试取消尚未开始的 Future，避免 Run 已标记失败后后台仍继续消耗带宽。

## 7. 自适应性能预算

默认设置：

- `request_concurrency = 8`
- `per_host_concurrency = 4`

PerformancePolicy 会把用户配置与设备档位合并：

| 档位 | Request 并发上限 | Host 上限 | Progress 最小间隔 | 结果批次 |
|---|---:|---:|---:|---:|
| Efficiency | 4 | 2 | 350 ms | 48 |
| Balanced | 8 | 4 | 180 ms | 32 |
| Quality/High | 用户配置（硬上限 64） | 用户配置（硬上限 32，且不超过全局） | 100 ms | 24 |

因此开启多线程不会撤销前一轮低端设备优化。

## 8. UI

Settings 新增“网页抓取并发”：

- 全局请求并发；
- 单 Host 并发上限；
- 当前设备策略说明。

Task Editor 的目标 URL 改为多行输入，一行一个 URL。重复 URL 在保存前按原顺序去重。一个 Task 的 HTTP Method、Headers、Body、Parser/Field 配置默认共享到这些 URL。

## 9. Repair Center 与配置容错

AppSettings 对并发参数做强制归一化：

- 全局 1..64；
- Host 1..32；
- Host <= 全局。

StartupHealthScanner 会报告越界以及 Host 大于全局的不一致。Repair Center 修复设置时会安全收敛，不会关闭并发功能；“性能/动画”修复会恢复到 8/4 的安全默认值。

## 10. 验证重点

专项测试覆盖：

1. 同 Host 多 URL 确实并发且不超过 Host 上限；
2. 多 Host 能利用全局 Worker Pool；
3. 单请求失败不会拖垮整批；
4. Cancel 能协作停止并发 Worker；
5. 使用本地 ThreadingHTTPServer 验证真实 HttpFetcher 并发；
6. 多 Run 共享同一 Host 上限；
7. Run 到达终态后 Pause/Resume/Cancel 不破坏终态；
8. 并发配置 clamp 与 Host<=Global；
9. Repair/Health Scanner 能发现不一致并安全修复；
10. CancellationToken Pause/Resume/Cancel 的线程安全行为。

## 11. 已知边界

- 当前普通 Task Editor 把多 URL 视为共享同一套 Method/Headers/Body/字段规则的批量 Request。若需要每个 URL 完全不同的 RequestSpec，仍应通过任务包/高级工作流编辑，而不是普通批量输入框。
- 这不是自动递归抓取器；未来若加入 URL Frontier/robots.txt/crawl-delay/去重 Bloom Filter，需要单独的 Crawler Scheduler，而不能简单扩大 ThreadPool。
- 并发越高不一定越快。目标站点限流、带宽、DNS、TLS、服务器能力、SQLite 写入和本机 CPU 都会成为瓶颈；因此默认保持受控而非无限并发。
