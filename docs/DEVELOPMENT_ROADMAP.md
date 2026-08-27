# Arenyxa V6.0 开发路线与交付门禁

| 阶段 | 范围 | 完成证据 |
|---|---|---|
| V6-P0 | Domain、SQLite Migration、应用壳、Browser Capture、基础网络工作区 | 模型/迁移/过滤/脱敏/Qt shell 测试 |
| V6-P1 | tshark/dumpcap、Process Monitor、Waterfall、Replay、TLS/DNS、HAR | 本地 HAR fixture、mock HTTP、dropped/backpressure、无驱动降级测试 |
| V6-P2 | Planner、API/Website Map、Revision、Database Adapter、Visualization、安全/兼容/性能 | 确定性算法单测、百万级 diff/分页预算、图表截图 |
| V6-P3 | `.arenyxa`、Headless/RBAC、Workflow、Marketplace、Terminal、Regression、Profile、Sandbox | Zip traversal、权限、token、Job budget、Docker/REST 测试 |
| V6-P4 | Liquid Glass、Spring/Morph、Edge Flow、刷新节奏、Reduce Motion、六主题 | 60/120Hz 帧预算、主题状态保持、RTL/DPI、视觉回归 |
| Release | compile/import/test/package/install/uninstall | PyInstaller、Inno Setup、干净 Windows x64 启动、快捷方式、文件关联、卸载 |

每次发布依次执行：

1. 语法/编译/依赖检查。
2. 模块边界、数据库迁移、数据流、状态机和 UI 逻辑检查。
3. 高吞吐、十万/百万级 fixture、内存、线程取消、帧预算检查。
4. Windows x64、高 DPI、PyInstaller、安装/升级/卸载、无开发机路径依赖检查。

任何阶段失败不得以删除数据、清空配置、关闭错误报告或静默降级绕过。

