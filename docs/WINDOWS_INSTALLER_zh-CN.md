# Arenyxa v0.1 Windows 构建与安装验证

当前目标：`v0.1` / 包版本 `0.1.0` / PE `0.1.0.0`。状态为 **candidate、community unsigned、NOT READY FOR RELEASE**。本指南描述构建输入和验收步骤，不代表已经完成安装、签名、升级或发布。

## 现代构建输入

- Python 3.11–3.13 x64、项目声明的现代依赖与 PyInstaller 6.x。
- Inno Setup 6 或 7；使用的具体编译器及产物哈希必须写入该次构建证据。
- 与最终源码一致的修复种子和源清单；修改源码后应重新生成并核对最终安装载荷。

```powershell
.\scripts\bootstrap.ps1 -SkipBrowserRuntime
.\.venv\Scripts\python.exe -B .\scripts\verify_release_identity.py
.\scripts\test.ps1
.\scripts\build.ps1 -RequireInno
```

预期输出：`dist/Arenyxa/Arenyxa.exe`、同目录服务组件，以及 `dist/installer/Arenyxa_v0.1_Setup_x64.exe`。身份门禁 PASS 仅说明源码元数据一致；构建完成后仍需读取实际 EXE/Installer 的版本属性、签名状态、哈希和载荷。`-SkipTests` 不能替代发布测试。

## 安装定义的实际行为

现代与 legacy 安装定义均保留原 AppId `{62ED5A19-19D3-402F-8819-D06C9D4A768B}`；默认目录表达式为 `{autopf}\Arenyxa`。默认最低权限安装，并允许选择管理员模式。实际安装目录随安装模式解析，不能仅根据源码推断已经验证所有权限组合。

安装器提供中英文界面、自选桌面快捷方式、开始菜单入口、`.arenyxa` 文件关联与卸载入口。现代安装器仅在管理员模式下提供可选 Windows Service 安装任务。`[Code]` 未实现旧 EXE 清理；不能宣称安装成功后会执行额外旧程序删除。

`[UninstallRun]` 会尝试移除现代服务。源码没有静默删除用户数据目录的卸载规则；实际卸载后数据、服务、快捷方式与关联的结果必须在干净环境中核验。默认应用数据根由 `AppPaths` 决定，可通过 `--data-dir` 显式指定独立验证目录。

## Candidate 验收记录

在干净 Windows 虚拟机或可恢复测试机上分别记录每步的系统版本、权限、结果、日志与截图：

1. 读取实际安装器/EXE 的 `0.1.0`、`0.1.0.0` 元数据与签名状态；首次安装，确认程序文件及首次启动。
2. `Arenyxa.exe --version` 显示 `Arenyxa 0.1`；该命令不能证明 GUI 正常。
3. 非管理员启动、关闭、重启；在中英文、DPI、主题与 Reduce Motion 条件下检查关键工作流。
4. 创建任务、运行/取消、查看数据、导出，并核对预期磁盘结果；记录缺失抓包/浏览器依赖时的提示。
5. 从实际旧工程版本覆盖安装，核对迁移、保留数据与失败恢复。8.x → 0.1 的数字回退没有已验证的升级结论；先备份并在可丢弃环境验证。
6. 卸载后检查服务、快捷方式、文件关联和安装目录，并证明用户数据按约定保留。

本轮环境调查未找到可直接使用的干净 Windows VM。源码启动、单元测试、offscreen UI 或普通开发机安装不能替代干净机器验收。最终证据产生前保持 `NOT TESTED` / `BLOCKED`。

## 签名与信任

本候选版按 **community unsigned** 处理。不得把 Developer Root、Owner、Enterprise Root 凭据用于产品发布签名；也不得把签名密钥、密码、私有证书或真实数据打包到发行物。Release Attestation 与 Windows Authenticode 是不同验证机制，任意一项存在都不能代替另一项的实测结果。当前指南不执行或宣称已完成签名。

## Legacy lane

`legacy/win7` 使用 Python 3.8 / PySide2 冻结实现，目标是 Windows 7 SP1 x64 兼容环境。定义的安装器名为 `Arenyxa_v0.1_Legacy_Win7_x64_Setup.exe`，构建入口为 `scripts/build-win7.ps1`。元数据已统一，但 **legacy 构建、真实运行和安装均 NOT TESTED**。现代源码或 Python 3.8 语法检查通过不等于 legacy 环境验证。
