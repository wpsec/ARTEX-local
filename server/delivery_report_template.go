package server

import (
	"fmt"
	"strings"

	"github.com/wpsec/ARTEX-local/agent"
)

// Fenced packets and HTML comments can contain Markdown-looking evidence. They
// must not satisfy report headings or be mistaken for our generated appendix.
func walkDeliveryMarkdown(report string, visit func(line string, offset int)) bool {
	return scanDeliveryMarkdown(report, func(line string, offset int, code bool) {
		if !code {
			visit(line, offset)
		}
	})
}

func scanDeliveryMarkdown(report string, visit func(line string, offset int, code bool)) bool {
	var fence byte
	fenceLength := 0
	inComment := false
	for offset := 0; offset < len(report); {
		end := strings.IndexByte(report[offset:], '\n')
		next := len(report)
		if end >= 0 {
			next = offset + end + 1
			end += offset
		} else {
			end = len(report)
		}
		line := strings.TrimSuffix(report[offset:end], "\r")
		start := offset
		offset = next
		if fence != 0 {
			trimmed := strings.TrimSpace(line)
			run := 0
			for run < len(trimmed) && trimmed[run] == fence {
				run++
			}
			if !deliveryIndentedCode(line) && run >= fenceLength && strings.TrimSpace(trimmed[run:]) == "" {
				fence, fenceLength = 0, 0
			} else {
				visit(line, start, true)
			}
			continue
		}
		if deliveryIndentedCode(line) && !inComment {
			visit(line, start, true)
			continue
		}
		if !inComment {
			if marker, length := deliveryOpeningFence(line); marker != 0 {
				fence, fenceLength = marker, length
				continue
			}
		}
		if !inComment && strings.TrimSpace(line) == deliveryEvidenceAppendixMarker {
			visit(line, start, false)
			continue
		}
		line = deliveryVisibleLine(line, &inComment)
		if deliveryIndentedCode(line) {
			continue
		}
		visit(line, start, false)
	}
	return fence == 0 && !inComment
}

func deliveryOpeningFence(line string) (byte, int) {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) < 3 || (trimmed[0] != '`' && trimmed[0] != '~') {
		return 0, 0
	}
	run := 1
	for run < len(trimmed) && trimmed[run] == trimmed[0] {
		run++
	}
	if run < 3 || (trimmed[0] == '`' && strings.ContainsRune(trimmed[run:], '`')) {
		return 0, 0
	}
	return trimmed[0], run
}

func deliveryIndentedCode(line string) bool {
	left := strings.TrimLeft(line, " ")
	return len(line)-len(left) >= 4 || strings.HasPrefix(left, "\t")
}

func deliveryVisibleLine(line string, inComment *bool) string {
	if !*inComment && !strings.Contains(line, "<!--") {
		return line
	}
	visible := []byte(line)
	for i := 0; i < len(line); {
		if *inComment {
			end := strings.Index(line[i:], "-->")
			next := len(line)
			if end >= 0 {
				next = i + end + 3
				*inComment = false
			}
			for j := i; j < next; j++ {
				visible[j] = ' '
			}
			i = next
			continue
		}
		if strings.HasPrefix(line[i:], "<!--") {
			*inComment = true
			continue
		}
		if line[i] == '`' {
			run := 1
			for i+run < len(line) && line[i+run] == '`' {
				run++
			}
			end := i + run
			matched := false
			for end < len(line) {
				if line[end] != '`' {
					end++
					continue
				}
				length := 1
				for end+length < len(line) && line[end+length] == '`' {
					length++
				}
				end += length
				if length == run {
					i = end
					matched = true
					break
				}
			}
			if !matched {
				i += run
			}
			continue
		}
		i++
	}
	return string(visible)
}

func deliverySectionHasContent(body string) bool {
	hasContent := false
	scanDeliveryMarkdown(body, func(line string, _ int, code bool) {
		trimmed := strings.TrimSpace(line)
		level, _ := deliveryMarkdownHeading(line)
		if trimmed != "" && trimmed != deliveryEvidenceAppendixMarker && (code || level == 0) {
			hasContent = true
		}
	})
	return hasContent
}

func deliveryMarkdownHeading(line string) (int, string) {
	line = strings.TrimSpace(line)
	level := 0
	for level < len(line) && line[level] == '#' {
		level++
	}
	if level == 0 || level == len(line) || (line[level] != ' ' && line[level] != '\t') {
		return 0, ""
	}
	text := strings.TrimSpace(line[level:])
	if suffix := strings.TrimRight(text, "#"); len(suffix) < len(text) && strings.HasSuffix(suffix, " ") {
		text = strings.TrimSpace(suffix)
	}
	return level, text
}

func validateDeliveryReportTemplate(report, expectedVector string) error {
	report = stripDeliveryTrafficEvidence(report)
	sections := strings.Split(agent.DeliveryReportSectionOrder, "、")
	subsections := []struct {
		section string
		title   string
		seen    bool
	}{
		{section: "描述", title: "定级依据"},
		{section: "测试过程", title: "发现过程与攻击思路"},
		{section: "测试过程", title: "失败尝试与未验证项"},
		{section: "证据说明", title: "Burp 复现"},
		{section: "证据说明", title: "复测标准"},
	}
	sectionIndex, bodyStart := -1, 0
	subsectionIndex, subsectionStart := -1, 0
	title, name, cvss := false, false, false
	var problem string
	checkSubsection := func(end int) {
		if subsectionIndex >= 0 && !deliverySectionHasContent(report[subsectionStart:end]) {
			problem = "“" + subsections[subsectionIndex].title + "”子节为空"
		}
		subsectionIndex = -1
	}
	closed := walkDeliveryMarkdown(report, func(line string, offset int) {
		if problem != "" {
			return
		}
		level, text := deliveryMarkdownHeading(line)
		if level >= 1 && level <= 3 {
			checkSubsection(offset)
			if problem != "" {
				return
			}
		}
		if level == 1 {
			if title || sectionIndex >= 0 || text == "" {
				problem = "只能在报告头保留一个非空一级标题"
				return
			}
			title = true
		}
		if level == 2 {
			if sectionIndex >= 0 && !deliverySectionHasContent(report[bodyStart:offset]) {
				problem = "“" + sections[sectionIndex] + "”章节为空"
				return
			}
			next := sectionIndex + 1
			if next >= len(sections) || text != sections[next] {
				problem = "二级标题缺失、重复或顺序错误：“" + text + "”"
				return
			}
			sectionIndex = next
			bodyStart = offset + len(line)
			return
		}
		if level == 3 && sectionIndex >= 0 {
			for i := range subsections {
				subsection := &subsections[i]
				if subsection.section != sections[sectionIndex] || subsection.title != text {
					continue
				}
				if subsection.seen {
					problem = "重复的子标题：“" + text + "”"
					return
				}
				subsection.seen = true
				subsectionIndex, subsectionStart = i, offset+len(line)
			}
		}
		if sectionIndex < 0 {
			trimmed := strings.TrimSpace(line)
			for _, prefix := range []string{"漏洞名称：", "漏洞名称:"} {
				if strings.HasPrefix(trimmed, prefix) && strings.TrimSpace(strings.TrimPrefix(trimmed, prefix)) != "" {
					name = true
				}
			}
			for _, prefix := range []string{"CVSS 4.0：", "CVSS 4.0:"} {
				if strings.HasPrefix(trimmed, prefix) {
					fields := strings.Fields(strings.TrimPrefix(trimmed, prefix))
					if len(fields) > 0 {
						vector, valid := normalizeCVSS4BaseVector(fields[0])
						if cvss || (valid && vector != expectedVector) {
							problem = "CVSS 报告头重复或与 cvss_vector 参数不一致"
							return
						}
						cvss = cvss || valid
					}
				}
			}
		}
	})
	if problem == "" {
		checkSubsection(len(report))
	}
	if problem == "" && !closed {
		problem = "代码块或 HTML 注释未闭合"
	}
	if problem == "" && (!title || !name || !cvss) {
		problem = "报告头须包含一级标题、非空“漏洞名称：”及“CVSS 4.0：”完整 Base 向量"
	}
	if problem == "" && sectionIndex != len(sections)-1 {
		problem = "缺少必需章节"
	}
	if problem == "" && !deliverySectionHasContent(report[bodyStart:]) {
		problem = "“证据说明”章节为空"
	}
	if problem == "" {
		var missing []string
		for _, subsection := range subsections {
			if !subsection.seen {
				missing = append(missing, subsection.section+"/"+subsection.title)
			}
		}
		if len(missing) > 0 {
			problem = "缺少必需三级标题：" + strings.Join(missing, "、")
		}
	}
	if problem != "" {
		return fmt.Errorf("交付报告格式不符合固定模板：%s；二级标题必须按顺序为：%s。请保留各节，证据不足写“未验证”，补齐后重新保存", problem, agent.DeliveryReportSectionOrder)
	}
	return nil
}
