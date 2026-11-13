import { CopyButton } from "@/components/copy-button";
import { Markdown } from "@/components/markdown";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { applyCVSSMetadata } from "@/lib/delivery-report";

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
        {report ? <CopyButton text={report} label="复制交付报告" successMessage="已复制交付报告" /> : null}
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
          <p className="text-muted-foreground text-sm">
            {hasDetailedReport
              ? "该详细报告生成时尚未包含交付报告；已有报告不会自动补写。"
              : "交付报告会由报告 Agent 与详细报告一并生成。"}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
