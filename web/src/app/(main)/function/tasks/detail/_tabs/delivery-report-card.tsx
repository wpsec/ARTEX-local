"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, SaveIcon, SparklesIcon } from "lucide-react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { scoreCVSS4Base } from "@/lib/cvss-v4";
import type { Finding, FindingDeliveryDraft, FindingDeliveryReport } from "@/lib/types";
import { copyText } from "@/lib/utils";

type EditorState = Pick<FindingDeliveryReport, "content" | "cvss_vector" | "evidence_version"> & {
  current_evidence_version: number;
};

type SavedState = Pick<EditorState, "content" | "cvss_vector" | "evidence_version">;

const displayName = (finding: Finding) =>
  (finding.name?.trim() || finding.vulnclass || "未命名漏洞").replace(/[\r\n]+/g, " ");

function codeFence(language: string, value: string): string {
  const runs = value.match(/`+/g) ?? [];
  const fence = "`".repeat(Math.max(3, ...runs.map((run) => run.length + 1)));
  return `${fence}${language}\n${value}\n${fence}`;
}

function buildDraftMarkdown(finding: Finding, draft: FindingDeliveryDraft): string {
  return [
    `# 漏洞名称：${displayName(finding)}`,
    "",
    `- **CVSS 4.0 Base 向量（CVSS-B）**：${draft.cvss_vector}`,
    "- **CVSS 4.0 评分**：待计算",
    "- **漏洞等级**：待计算",
    "",
    "## 漏洞描述",
    "",
    draft.description,
    "",
    "## 修复建议",
    "",
    draft.remediation,
    "",
    "## 测试过程",
    "",
    draft.test_process,
    "",
    "### 攻击链路",
    "",
    codeFence("text", draft.attack_chain),
    "",
    "### 发现路径说明",
    "",
    draft.discovery_path,
    "",
    "### Burp 复测请求",
    "",
    codeFence("http", draft.request_packet),
    "",
    "### 返回包",
    "",
    codeFence("http", draft.response_packet),
    "",
  ].join("\n");
}

function updateCVSSMetadata(content: string, vector: string, score: ReturnType<typeof scoreCVSS4Base>): string {
  const metadata = [
    `- **CVSS 4.0 Base 向量（CVSS-B）**：${vector.trim()}`,
    `- **CVSS 4.0 评分**：${score ? `${score.score.toFixed(1)}（CVSS-B）` : "待补全"}`,
    `- **漏洞等级**：${score?.severity ?? "待补全"}`,
  ];
  const patterns = [
    /^- \*\*CVSS 4\.0 Base 向量（CVSS-B）\*\*：.*$/m,
    /^- \*\*CVSS 4\.0 评分\*\*：.*$/m,
    /^- \*\*漏洞等级\*\*：.*$/m,
  ];
  let next = content;
  const missing: string[] = [];
  for (let i = 0; i < patterns.length; i++) {
    if (patterns[i].test(next)) next = next.replace(patterns[i], metadata[i]);
    else missing.push(metadata[i]);
  }
  if (missing.length > 0) {
    const headingEnd = next.indexOf("\n");
    if (headingEnd >= 0)
      next = `${next.slice(0, headingEnd + 1)}\n${missing.join("\n")}\n${next.slice(headingEnd + 1)}`;
    else next = `${missing.join("\n")}\n\n${next}`;
  }
  return next;
}

export function DeliveryReportCard({ taskId }: { taskId: string }) {
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [selectedId, setSelectedId] = React.useState("");
  const [editors, setEditors] = React.useState<Record<string, EditorState>>({});
  const [saved, setSaved] = React.useState<Record<string, SavedState>>({});
  const [loadingFindings, setLoadingFindings] = React.useState(true);
  const [loadingReport, setLoadingReport] = React.useState(false);
  const [generating, setGenerating] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const loaded = React.useRef(new Set<string>());

  React.useEffect(() => {
    let active = true;
    setLoadingFindings(true);
    api
      .findings(taskId)
      .then((items) => {
        if (!active) return;
        const byId = new Map<string, Finding>();
        for (const item of items) {
          if (item.finding_id) byId.set(item.finding_id, item);
        }
        const available = Array.from(byId.values());
        setFindings(available);
        setSelectedId((current) => (current && byId.has(current) ? current : (available[0]?.finding_id ?? "")));
      })
      .catch((error) => {
        if (active) toast.error(error instanceof Error ? error.message : "读取任务漏洞失败");
      })
      .finally(() => {
        if (active) setLoadingFindings(false);
      });
    return () => {
      active = false;
    };
  }, [taskId]);

  React.useEffect(() => {
    if (!selectedId || loaded.current.has(selectedId)) return;
    let active = true;
    setLoadingReport(true);
    api
      .findingDeliveryReport(taskId, selectedId)
      .then((report) => {
        if (!active) return;
        const evidenceVersion = report.exists ? report.evidence_version : report.current_evidence_version;
        const editor: EditorState = {
          content: report.content,
          cvss_vector: report.cvss_vector,
          evidence_version: evidenceVersion,
          current_evidence_version: report.current_evidence_version,
        };
        setEditors((current) => ({ ...current, [selectedId]: editor }));
        setSaved((current) => ({
          ...current,
          [selectedId]: {
            content: report.content,
            cvss_vector: report.cvss_vector,
            evidence_version: evidenceVersion,
          },
        }));
        loaded.current.add(selectedId);
      })
      .catch((error) => {
        if (active) toast.error(error instanceof Error ? error.message : "读取交付报告失败");
      })
      .finally(() => {
        if (active) setLoadingReport(false);
      });
    return () => {
      active = false;
    };
  }, [taskId, selectedId]);

  const finding = findings.find((item) => item.finding_id === selectedId);
  const editor = editors[selectedId];
  const score = editor ? scoreCVSS4Base(editor.cvss_vector) : null;
  const savedState = saved[selectedId];
  const dirty = Boolean(
    editor &&
      (editor.content !== savedState?.content ||
        editor.cvss_vector !== savedState?.cvss_vector ||
        editor.evidence_version !== savedState?.evidence_version),
  );
  const stale = Boolean(editor && editor.evidence_version !== editor.current_evidence_version);

  function updateEditor(update: (current: EditorState) => EditorState) {
    if (!selectedId) return;
    setEditors((current) => {
      const existing = current[selectedId];
      return existing ? { ...current, [selectedId]: update(existing) } : current;
    });
  }

  async function generate() {
    if (!finding || !selectedId) return;
    setGenerating(true);
    try {
      const draft = await api.generateFindingDeliveryReport(taskId, selectedId);
      const content = buildDraftMarkdown(finding, draft);
      const nextEditor: EditorState = {
        content: updateCVSSMetadata(content, draft.cvss_vector, scoreCVSS4Base(draft.cvss_vector)),
        cvss_vector: draft.cvss_vector,
        evidence_version: draft.evidence_version,
        current_evidence_version: draft.evidence_version,
      };
      setEditors((current) => ({ ...current, [selectedId]: nextEditor }));
      loaded.current.add(selectedId);
      toast.success("交付报告草稿已生成，请复核内容和 CVSS 评分");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "生成交付报告失败");
    } finally {
      setGenerating(false);
    }
  }

  async function save() {
    if (!editor || !score || !selectedId || stale) return;
    setSaving(true);
    try {
      const content = updateCVSSMetadata(editor.content, score.vector, score);
      const report = await api.saveFindingDeliveryReport(taskId, selectedId, {
        content,
        cvss_vector: score.vector,
        evidence_version: editor.evidence_version,
      });
      const nextEditor: EditorState = {
        content: report.content,
        cvss_vector: report.cvss_vector,
        evidence_version: report.evidence_version,
        current_evidence_version: report.current_evidence_version,
      };
      setEditors((current) => ({ ...current, [selectedId]: nextEditor }));
      setSaved((current) => ({
        ...current,
        [selectedId]: {
          content: report.content,
          cvss_vector: report.cvss_vector,
          evidence_version: report.evidence_version,
        },
      }));
      toast.success("交付报告已保存");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存交付报告失败");
    } finally {
      setSaving(false);
    }
  }

  async function copy() {
    if (!editor?.content) return;
    const ok = await copyText(editor.content);
    if (!ok) {
      toast.error("复制失败，请手动选择文本复制");
      return;
    }
    setCopied(true);
    toast.success("已复制交付报告 Markdown");
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-3">
        <div>
          <CardTitle className="flex items-center gap-2 text-sm">
            <SparklesIcon className="size-4" /> 交付报告（单漏洞 Markdown）
          </CardTitle>
          <p className="mt-1 text-muted-foreground text-xs">面向开发修复，生成后可编辑、复核、保存和复制。</p>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="grid min-w-64 flex-1 gap-1.5 text-muted-foreground text-xs">
            选择漏洞
            <select
              className="h-9 rounded-md border bg-background px-3 text-foreground text-sm"
              value={selectedId}
              onChange={(event) => setSelectedId(event.target.value)}
              disabled={loadingFindings || findings.length === 0}
            >
              {findings.length === 0 ? (
                <option value="">{loadingFindings ? "正在读取漏洞…" : "当前任务没有可生成报告的漏洞"}</option>
              ) : null}
              {findings.map((item) => (
                <option key={item.finding_id} value={item.finding_id}>
                  {displayName(item)}
                  {item.inherited ? "（继承）" : ""} · {item.severity || "未评级"}
                </option>
              ))}
            </select>
          </label>
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={generate}
              disabled={!selectedId || generating || loadingReport}
            >
              <SparklesIcon /> {generating ? "生成中…" : "生成草稿"}
            </Button>
            <Button size="sm" onClick={save} disabled={!editor?.content || !score || stale || saving || !dirty}>
              <SaveIcon /> {saving ? "保存中…" : "保存"}
            </Button>
            {editor?.content ? (
              <Button size="sm" variant="outline" onClick={copy}>
                {copied ? <CheckIcon /> : <CopyIcon />} 复制
              </Button>
            ) : null}
          </div>
        </div>

        {loadingReport ? <p className="text-muted-foreground text-xs">正在读取已保存的交付报告…</p> : null}
        {stale ? (
          <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-amber-700 text-sm dark:text-amber-300">
            漏洞证据已更新。请重新生成报告并复核后保存，避免交付内容引用旧证据。
          </p>
        ) : null}
        {editor && !score ? (
          <p className="text-destructive text-sm">CVSS 4.0 Base 向量格式无效或不完整，无法计算评分。</p>
        ) : null}

        {editor ? (
          <>
            <div className="grid gap-3 rounded-md border p-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
              <label className="grid gap-1.5 text-muted-foreground text-xs">
                CVSS 4.0 Base 向量（可编辑）
                <input
                  className="h-9 rounded-md border bg-background px-3 font-mono text-foreground text-xs"
                  value={editor.cvss_vector}
                  onChange={(event) => {
                    const vector = event.target.value;
                    const calculated = scoreCVSS4Base(vector);
                    updateEditor((current) => ({
                      ...current,
                      cvss_vector: vector,
                      content: updateCVSSMetadata(current.content, vector, calculated),
                    }));
                  }}
                  aria-label="CVSS 4.0 Base 向量"
                />
              </label>
              <div className="min-w-40 text-sm">
                <span className="text-muted-foreground">CVSS-B：</span>
                <strong>{score ? `${score.score.toFixed(1)} · ${score.severity}` : "待补全"}</strong>
              </div>
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              <label className="grid gap-2 font-medium text-muted-foreground text-xs">
                Markdown 编辑
                <textarea
                  className="min-h-[55vh] resize-y rounded-md border bg-background p-3 font-mono text-foreground text-xs leading-5"
                  value={editor.content}
                  onChange={(event) => updateEditor((current) => ({ ...current, content: event.target.value }))}
                  placeholder="点击“生成草稿”，或粘贴 Markdown 报告内容。"
                />
              </label>
              <div className="grid min-h-[55vh] grid-rows-[auto_1fr] gap-2 font-medium text-muted-foreground text-xs">
                <span>Markdown 预览</span>
                <div className="max-h-[60vh] min-h-0 overflow-auto rounded-md border bg-muted/20 p-4 text-foreground">
                  {editor.content ? <Markdown text={editor.content} /> : <p>暂无报告内容</p>}
                </div>
              </div>
            </div>
            <p className="text-muted-foreground text-xs">
              AI 内容和 CVSS 向量都需要人工复核；CVSS-B 按基础指标计算，不包含环境和威胁指标。
              {dirty ? " 当前修改尚未保存。" : ""}
            </p>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
