# Arenyxa 安装

Arenyxa v0.1 已作为公共源码版本发布准备完成。Windows 分发保持 **community unsigned**；源码发布不等于 Authenticode 签名，也不声明已经完成独立干净机器安装资格验证。

安装器说明、依赖边界和升级限制见 [Windows 安装指南](WINDOWS_INSTALLER_zh-CN.md)，当前发布范围见 [Release Status](RELEASE_STATUS.md)。

## 源码开发环境

在受支持的 Windows x64 环境中运行：

```powershell
.\scripts\bootstrap.ps1 -SkipBrowserRuntime
.\.venv\Scripts\python.exe -B .\scripts\verify_release_identity.py
```

可选浏览器、Npcap/TShark、PostgreSQL 和企业运行时必须按实际环境单独验证。不要把开发机环境当作独立 clean-machine 证据。

## 构建

```powershell
.\scripts\build.ps1 -RequireInno
```

发布源身份为 `v0.1` / package `0.1.0` / Windows `0.1.0.0`。构建成功、文件哈希正确和源码发布就绪，不应被解释为所有安装、升级、回滚或卸载场景均已验证。
