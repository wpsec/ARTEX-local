import { scoreCVSS4Base } from "./cvss-v4";

const metadataPatterns = [
  /^- \*\*CVSS 4\.0 Base 向量（CVSS-B）\*\*：.*$/,
  /^- \*\*CVSS 4\.0 评分\*\*：.*$/,
  /^- \*\*漏洞等级\*\*：.*$/,
  /^CVSS 4\.0[：:].*$/,
];

export function applyCVSSMetadata(content: string, vector: string): string {
  if (!vector || !content.trim()) return content;
  const score = scoreCVSS4Base(vector);
  const scoreText = score ? score.score.toFixed(1) : "待计算";
  const severity = score ? score.severity : "待计算";
  const singleLine = `CVSS 4.0：${vector}  评分 ${scoreText}（${severity}）`;
  const legacyLines = [
    `- **CVSS 4.0 Base 向量（CVSS-B）**：${vector}`,
    `- **CVSS 4.0 评分**：${score ? `${score.score.toFixed(1)}（CVSS-B）` : "待计算"}`,
    `- **漏洞等级**：${severity}`,
  ];
  const lines = content.split("\n");
  const metadata = new Map<number, number>();
  let bodyStart = lines.length;
  let titleIndex = -1;
  let fence = "";

  // 只改报告头，避免把请求、响应正文中的同名字段当作评分信息改写。
  for (const [index, line] of lines.entries()) {
    const fenceMatch = /^\s*(`{3,}|~{3,})(.*)$/.exec(line);
    if (fenceMatch) {
      const marker = fenceMatch[1];
      if (!fence) fence = marker;
      else if (marker[0] === fence[0] && marker.length >= fence.length && !fenceMatch[2].trim()) fence = "";
      continue;
    }
    if (fence) continue;
    if (/^ {0,3}##(?:\s|$)/.test(line)) {
      bodyStart = index;
      break;
    }
    if (titleIndex < 0 && /^ {0,3}#\s+/.test(line)) titleIndex = index;
    const kind = metadataPatterns.findIndex((pattern) => pattern.test(line.replace(/\r$/, "")));
    if (kind >= 0) metadata.set(index, kind);
  }

  const useSingleLine = [...metadata.values()].includes(3) || metadata.size === 0;
  const written = new Set<number>();
  const header: string[] = [];
  let titleEnd = 0;
  for (const [index, line] of lines.slice(0, bodyStart).entries()) {
    const kind = metadata.get(index);
    if (kind === undefined) header.push(line);
    else if (useSingleLine) {
      if (kind === 3 && !written.has(3)) {
        written.add(3);
        header.push(singleLine);
      }
    } else if (!written.has(kind)) {
      written.add(kind);
      header.push(legacyLines[kind]);
    }
    if (index === titleIndex) titleEnd = header.length;
  }
  let missing = legacyLines.filter((_, index) => !written.has(index));
  if (useSingleLine) missing = written.has(3) ? [] : [singleLine];
  if (missing.length) {
    header.splice(titleEnd, 0, "", ...missing, "");
  }
  return [...header, ...lines.slice(bodyStart)].join("\n");
}
