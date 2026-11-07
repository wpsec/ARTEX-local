import { CopyButton } from "@/components/copy-button";
import { Markdown } from "@/components/markdown";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { scoreCVSS4Base } from "@/lib/cvss-v4";

function applyCVSSMetadata(content: string, vector: string): string {
  if (!vector) return content;
  const score = scoreCVSS4Base(vector);
  const lines = [
    `- **CVSS 4.0 Base 向量（CVSS-B）**：${vector}`,
    `- **CVSS 4.0 评分**：${score ? `${score.score.toFixed(1)}（CVSS-B）` : "待计算"}`,
    `- **漏洞等级**：${score?.severity ?? "待计算"}`,
  ];
  const patterns = [
    /^- \*\*CVSS 4\.0 Base 向量（CVSS-B）\*\*：.*$/m,
    /^- \*\*CVSS 4\.0 评分\*\*：.*$/m,
    /^- \*\*漏洞等级\*\*：.*$/m,
  ];
  let result = content;
  const missing: string[] = [];
  for (let index = 0; index < patterns.length; index++) {
    if (patterns[index].test(result)) result = result.replace(patterns[index], lines[index]);
    else missing.push(lines[index]);
  }
  if (missing.length > 0) {
    const headingEnd = result.indexOf("\n");
    result = headingEnd >= 0
      ? `${result.slice(0, headingEnd + 1)}\n${missing.join("\n")}\n${result.slice(headingEnd + 1)}`
      : `${missing.join("\n")}\n\n${result}`;
  }
  return result;
}

export function DeliveryReportSection({
  content,
  cvssVector,
  stale,
  hasDetailedReport,
}: {
  content?: string;
  cvssVector?: string;
  stale?: boolean;
  hasDetailedReport: boolean;
}) {
  const report = content ? applyCVSSMetadata(content, cvssVector ?? "") : "";

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-3">
        <CardTitle className="text-sm">交付报告</CardTitle>
        {report ? (
          <CopyButton text={report} label="复制交付报告" successMessage="已复制交付报告" />
        ) : null}
      </CardHeader>
      <CardContent className="space-y-3">
        {stale ? (
          <Alert>
            <AlertDescription>漏洞证据已变化，交付报告可能引用旧证据。</AlertDescription>
          </Alert>
        ) : null}
        {report ? (
          <Markdown text={report} />
        ) : (
          <p className="text-sm text-muted-foreground">
            {hasDetailedReport
              ? "该详细报告生成时尚未包含交付报告；已有报告不会自动补写。"
              : "交付报告会由报告 Agent 与详细报告一并生成。"}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
