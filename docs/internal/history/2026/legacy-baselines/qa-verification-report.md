# Arenyxa v6.6 本地稳定源码工程验证报告

日期：2026-08-10

## 基线

最终工作树从用户本地稳定发布源码 `Arenyxa_V6.6_Stable_Release_Source.zip` 建立。后续品牌迁移、Developer Mode 双协议门禁、一键功能验证、压力稳定性测试及其修复均在该工作树上完成。

## 当前功能验证

- 内置 `test-all`：14/14 实际执行项通过。
- 高级能力 wiring：30/30 contract 可解析且实现方法存在。
- `stress-test quick`：最高 4 workers，0 error。
- `stress-test standard`：最高 12 workers，0 error。
- `stress-test extreme`：最高 64 workers，每级 600 次混合操作，0 error；在配置安全上限内未观察到崩溃。

## Python / 兼容性

- `compileall`：源码与测试通过。
- Python 3.8 grammar gate：87 个受检查 Python 文件通过。
- Modern / Windows 7 Legacy Qt scoped-enum 契约包含 Developer Mode 协议对话框所需的 `Ok` 映射。
- 公开入口：`python -m arenyxa --version` 输出 `Arenyxa 6.6`。
- 兼容入口：`python -m arenyxa --version` 同样输出 `Arenyxa 6.6`。
- Headless 公开入口 `python -m arenyxa.server --help` 可正常解析。

## 回归结果

在 Source Manifest 最终重生成前，所有不依赖该最终哈希文件的测试分片结果为：

- 分片 A：84 passed；
- 分片 B：122 passed，1 个 Qt 环境 skip；
- 分片 C：124 passed，4 个 Qt 环境 skip；
- 分片 D：46 passed，1 个 Qt 环境 skip；
- Source Manifest 最终哈希测试：1 passed。
- 最终同一 pytest 进程完整回归：377 passed，6 skipped，0 failed，40.39 秒；进程自然退出且未留下测试子进程。

6 个 skip 均来自当前审查环境没有受支持 Qt binding 的 GUI smoke/visual tests；这不是业务断言失败，也不能替代 Windows 原生 GUI 认证。

## Repair Seed

- Product：Arenyxa。
- 受保护文件：98。
- 新 `src/arenyxa` facade：已包含。
- 新 `developer_safety.py` / `developer_validation.py`：已包含。
- Seed SHA-256 ↔ manifest：匹配。
- ZIP CRC：通过。
- Repair Seed 内部文本禁用关键字扫描：0 命中。

## 构建产物验证

- Python wheel 成功构建：`arenyxa-6.6.0-py3-none-any.whl`。
- Wheel ZIP CRC：通过。
- Wheel 包含 Arenyxa 公共 facade、内部兼容实现、Developer Mode 双协议模块、完整功能验证模块和最新 Repair Seed。
- Wheel 不包含迁移前的旧品牌图片资源。
- Wheel 文本禁用关键字扫描：0 命中。

## 仍需原生 Windows 验证

当前容器不能诚实替代 Windows 10/11 或 Windows 7 SP1 x64 的真实 Qt、PyInstaller、Inno Setup 和系统驱动环境。正式二进制发布前必须在 Windows 上重新执行 `scripts\test.ps1` 与 `scripts\build.ps1`，并进行安装/升级/卸载、GUI、Repair Center、系统抓包与 Legacy lane 冒烟。
