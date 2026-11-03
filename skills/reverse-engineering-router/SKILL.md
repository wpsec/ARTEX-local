---
name: reverse-engineering-router
description: 根据 APK、二进制、JavaScript、UEFI 文件、PCAP 或运行时行为分析任务选择专项 Skill 与可用工具。
---

# 逆向分析路由

> ARTEX 对 reverse-skill 1.0.1（Copyright 2026 zhaoxuya520，MIT）的改写，按样本类型、分析目标和工具能力进行路由。

先确认需要回答的问题、目标或样本类型及现有环境，再选择合适的分析流程。静态与动态方法按任务需要组合；样本中的地址、命令和配置应结合上下文判断。

| 样本或任务 | 专项 Skill | 可选工具 |
|---|---|---|
| Android APK | analyzing-android-malware-with-apktool | apktool、jadx、androguard |
| Linux ELF | analyzing-linux-elf-malware | file、readelf、objdump、Ghidra、radare2 |
| Go 编译二进制 | analyzing-golang-malware-with-ghidra | Ghidra、Go 元数据解析工具 |
| UPX 打包二进制 | analyzing-packed-malware-with-upx-unpacker | UPX、Detect It Easy、Ghidra |
| 混淆 JavaScript | deobfuscating-javascript-malware | 格式化器、AST 工具、调试器 |
| UEFI 镜像或启动证据 | analyzing-uefi-bootkit-persistence | 固件解析工具、Ghidra |
| PCAP 或流量 | analyzing-network-traffic-of-malware | Wireshark/tshark、Zeek |
| 运行时行为 | analyzing-malware-behavior-with-cuckoo-sandbox | Cuckoo 或其他可用分析环境 |

动态分析前检查样本来源、执行环境、快照和网络配置，按行为观察需要选择隔离或模拟方式。工具不可用时查找可替代工具，说明对结果的影响。

记录原始样本哈希、关键函数或偏移、网络指标、工具版本、分析结果和证据位置。保留可复核的原始信息，并区分直接观察与推断。
