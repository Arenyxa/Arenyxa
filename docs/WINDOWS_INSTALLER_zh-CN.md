# Arenyxa V7.0 Windows 安装包制作教程

## 1. 工具

- Python 3.11、3.12 或 3.13 x64
- PyInstaller 6.x（由 dev extra 安装）
- Inno Setup 6 或 7
- 可选：Windows SDK `signtool.exe` 与代码签名证书

## 2. 准备与测试

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\bootstrap.ps1
.\.venv\Scripts\python.exe .\scripts\verify_v73_release_identity.py
.\scripts\test.ps1
```

只有全部门禁通过后才制作安装包。v7.0 的构建脚本也会在打包前再次执行 release-identity gate，阻止版本号、Windows 文件属性、Inno Setup 文件名或 Release Attestation 版本发生漂移。

## 3. Portable EXE 目录

```powershell
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean .\packaging\arenyxa.spec
```

输出：`dist\Arenyxa\Arenyxa.exe`。Spec 收集 PySide6 Qt 插件、lxml、openpyxl、DNS 与应用资源，排除浏览器运行时等超大可选组件。程序图标使用 `resources\icons\arenyxa.ico`；48 px 及以上保留完整核准图形，16/24/32 px 使用同一视觉语言的光学简化版本以保证 Windows 小图标可读性。`arenyxa.png` 使用 RGBA 透明外角，旧 `Arenyxa` 字样品牌图已从发行资源中移除；当前构建仅使用无文字的通用应用图标 `arenyxa.png` / `arenyxa.ico`。

在干净 Windows Sandbox/虚拟机中检查：

1. `Arenyxa.exe --version`
2. 首次启动目录与 SQLite 初始化
3. 100%/125%/150%/200% DPI
4. 六主题、RTL、Reduce Motion
5. 建任务 → 预览 → Run → 数据 → 导出
6. HAR 导入与无 packet-analysis runtime 时的可执行降级提示
7. 非管理员用户启动/退出

## 4. Inno Setup Installer

安装 Inno Setup 6 或 7 后运行：

```powershell
.\scripts\build.ps1
```

输出：`dist\installer\Arenyxa_V7.0_Setup_x64.exe`。

Installer 会：

- 安装到当前用户可写的 `{autopf}\Arenyxa`
- 创建开始菜单入口
- 可选创建桌面快捷方式
- 注册新的 `.arenyxa` 文件类型，并保留 `.arenyxa` 兼容打开命令
- 在 Windows 应用列表注册卸载程序
- 使用正式 Arenyxa 图标作为 Setup、快捷方式、应用和卸载显示图标
- 同 AppId 升级时不会在安装开始前删除旧 `Arenyxa.exe`；新 payload 成功进入 `ssPostInstall` 后才尝试清理旧 EXE，降低失败升级造成不可运行的风险

不把 packet-capture driver、packet-analysis runtime、Playwright Browser 或数据库驱动强制捆绑进基础安装包；这些能力在 UI 中有明确依赖检查和安装说明，基础安装体积保持可控。

## 5. 代码签名（发布建议）

在签名前先对构建产物做病毒扫描、SBOM 和依赖审查。使用组织证书：

```powershell
signtool sign /fd SHA256 /td SHA256 /tr https://timestamp.digicert.com /a .\dist\Arenyxa\Arenyxa.exe
signtool sign /fd SHA256 /td SHA256 /tr https://timestamp.digicert.com /a .\dist\installer\Arenyxa_V7.0_Setup_x64.exe
```

验证：

```powershell
signtool verify /pa /v .\dist\installer\Arenyxa_V7.0_Setup_x64.exe
```

不要把私钥或证书密码写入仓库、脚本、CI 日志或 `.arenyxa` / 兼容 `.arenyxa` 项目。

## 6. 升级与卸载测试

1. 安装旧版 fixture，创建 Task/Run/Result/Capture/Revision。
2. 安装 V7.0 覆盖升级；确认 migration 成功，历史事实不变。
3. 卸载应用；确认程序文件/快捷方式/关联清除。
4. 用户数据默认保留在 `%LOCALAPPDATA%\Arenyxa`，卸载程序不得静默删除。
5. 若产品未来增加“删除用户数据”选项，必须显示路径和影响范围并要求独立确认。

