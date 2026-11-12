---
name: owasp-top-10-testing
description: 按 OWASP Top 10:2025 或 OWASP API Security Top 10:2023 组织授权安全评估，并逐类说明 ARTEX 实际测试、证据与覆盖限制。用户要求 OWASP Top 10 评估、分类报告或合规映射时使用。
license: "Apache-2.0; includes OWASP material under CC-BY-3.0 and CC-BY-SA-4.0; see THIRD-PARTY-NOTICES.txt"
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
  source: https://github.com/usestrix/strix/tree/main/skills/owasp-top-10-testing
---

# OWASP Top 10 覆盖评估

> 改编说明：基于 usestrix/strix 的 `owasp-top-10-testing`（Apache-2.0），已翻译并改写为 ARTEX 工作流。

> OWASP 分类来源：[OWASP Top 10:2025](https://top10.owasp.org/2025/)（CC BY 3.0）和 [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x10-api-security-risks/)（CC BY-SA 4.0）。本文重排并选择分类名称，改写测试流程以适配 ARTEX；许可和改编说明见 `THIRD-PARTY-NOTICES.txt`。

本 skill 使用来源标注的 OWASP Top 10:2025 与 OWASP API Security Top 10:2023。若用户要求旧版或特定合规版本，先确认并在结果中准确标注版本。OWASP 是风险分类，不代表 ARTEX 能自动或完整测试每个类别。

用户只要求将已有发现映射到 OWASP 类别时，使用现有证据，不启动新扫描。用户要求对目标进行 OWASP 评估时，对授权范围内的 Web、API 或代码工作流调用对应专用 Skill；Web/API 测试由其工作流调用 ZAP，并如实标注未实际执行的类别。

## OWASP Top 10:2025 分类

按用户授权和 ARTEX 实际能力逐类制定有限测试意图：

| 类别 | 分类名称 |
| --- | --- |
| A01 | Broken Access Control（包含 SSRF） |
| A02 | Security Misconfiguration |
| A03 | Software Supply Chain Failures |
| A04 | Cryptographic Failures |
| A05 | Injection |
| A06 | Insecure Design |
| A07 | Authentication Failures |
| A08 | Software or Data Integrity Failures |
| A09 | Security Logging & Alerting Failures |
| A10 | Mishandling of Exceptional Conditions |

API 专项按 OWASP API Security Top 10:2023 对照 API1 BOLA、API3 Broken Object Property Level Authorization、API5 Broken Function Level Authorization 等类别，并使用 `api-security-testing` 的测试边界。

## 执行与覆盖记录

1. 先确认授权、目标、身份、测试数据、排除范围和操作约束；再选择 ARTEX 中实际可用的 Web、API 或代码工作流。
2. 将类别拆成受范围约束的 ARTEX 意图。不要为追求“十项覆盖”而扩大资产、执行高负载或触发真实业务副作用。
3. 每类单独记录：是否尝试、使用的证据、确认结果、限制、未评估原因。建议状态为“已确认”“有线索待验证”“未发现已确认问题”“未评估”。
4. 只有满足 ARTEX worker 的复现标准才登记漏洞；不能从外部验证的代码、配置或运营类问题不能标为“通过”。

**不要继承上游 Strix 对类别的强/部分覆盖判断。** ARTEX 的实际能力和本次任务证据可能不同，必须逐类依据当前工具与结果重新判断。

## 必须如实标注的覆盖边界

- A03 中供应链治理、构建链和发布链的完整评估通常需要 CI/CD、依赖或供应商材料；未提供时标为未评估或部分评估。
- A04 的静态存储加密和密钥管理通常需要源代码、基础设施或密钥管理证据；外部 Web 测试不足以判定。
- A06 的设计意图、A08 的构建信任边界、A09 的日志告警管线都可能超出在线黑盒任务范围；不能把不可见当作已通过。
- A10 的有限异常输入测试不等于覆盖所有内部异常路径；说明具体测试面和停止条件。
- A01、A07 等访问控制结论需要适当的测试身份和授权数据；缺少时须明确说明限制。

最终摘要先列确认的问题，再列待验证线索和未评估类别；不得因没有发现问题或任务提前结束而声称“已通过 OWASP 全项评估”。
