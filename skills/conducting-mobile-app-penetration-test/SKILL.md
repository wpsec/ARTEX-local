---
name: conducting-mobile-app-penetration-test
description: 结合静态分析、设备运行和后端 API 测试评估 Android 或 iOS 应用的安全性。
---

# 移动应用安全评估

> 改写自 Anthropic-Cybersecurity-Skills 的同名 Skill（上游 v1.0.0，作者 mahipal），适配 ARTEX 测试与证据流程。

1. 确认任务中的应用版本、设备或模拟器、账号和后端环境；记录可用工具和接入条件。
2. 检查应用包、权限、导出组件、深链、签名、网络安全配置、资源及 native library。Android APK 可结合 `analyzing-android-malware-with-apktool`。
3. 在测试设备上检查本地存储、会话生命周期、进程行为和网络流量；按需使用代理、动态插桩或调试工具验证客户端保护。
4. 测试认证、会话与 API 授权、数据传输和服务端校验，记录请求、响应、关键代码位置及可复现条件。
5. 区分静态线索与已在设备或后端验证的行为，记录测试版本、环境、影响和修复建议。
