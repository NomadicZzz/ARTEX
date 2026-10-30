package kb

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

const (
	defaultReportChunkRunes = 6000
	maxReportChunks         = 8
)

// DistillReportSystem asks the model for one component PoC and, when the chapter
// supports it, one reusable methodology. CVE sync and finding distillation keep
// their own prompts.
const DistillReportSystem = `你是资深安全研究员与渗透测试知识库架构师。输入材料是从一份已脱敏的渗透测试报告中提取的漏洞章节。
请将报告中的实战成果提炼为高复用价值的知识库条目，重点聚焦【可直接复用的组件 PoC】与【可迁移的漏洞挖掘经验/方法论】。

提炼原则：
1. 严禁把“报告摘要”、“影响与危害”、“证据罗列”、“受影响范围表”单独拆成碎片条目。同一个漏洞的所有上下文必须整合提炼。
2. 针对每个具体的漏洞实例，请按以下两个维度提炼（每个漏洞最多产出 1~2 条）：
   - 维度 A【组件专属 PoC 条目 (kind = "poc")】：当报告包含特定产品/组件/微服务的具体漏洞路径与请求报文时，提取其组件指纹、请求构造特征、关键 Header/Body 信封格式及判断依据，填入 poc_snippet 与 detection_guide。
   - 维度 B【通用挖掘经验/方法论条目 (kind = "methodology")】：当报告的“根因分析”或“复现过程”体现了具有普适性的攻击思路、认证绕过模式、参数构造技巧或网关反代绕过经验时，剥离具体目标厂商名称，将其抽象为跨系统通用的实战排查方法论。
3. 彻底抹除客户单位名称、真实人名、私有域名、IP、真实 session_id/corp_id，统一使用 <target-host>、<ip>、<corp-id>、<session-id> 占位。
4. 只输出合法的 JSON 数组，不要包裹 Markdown 代码块。数组每个元素严格包含以下字段：
[{"title":"精准的技术标题（不含客户名）","kind":"poc 或 methodology 或 checklist","vulnclass":"auth_bypass | rce | sqli | xss | ssrf | idor | info_leak | file_upload | logic","severity":"critical | high | medium | low | info","products":["小写标准组件名"],"tags":["小写技术标签"],"affected_versions":"受影响版本或组件栈说明","summary":"150字以内的核心原理、利用前提与挖掘切入点摘要","detection_guide":"结构化的实战探测与挖掘步骤","poc_snippet":"脱敏后的关键 HTTP 原始请求报文或最小化验证代码片段","remediation":"精炼的研发代码级与网关级修复建议"}]`

var (
	httpStartLine = regexp.MustCompile(`(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+\S+\s+HTTP/1\.[01]\b`)
	mdHeadRe      = regexp.MustCompile(`^(#{1,6})\s+(.+?)\s*$`)
	cnOrdRe       = regexp.MustCompile(`^([一二三四五六七八九十百]+)、\s*(.*)$`)
	cnParenRe     = regexp.MustCompile(`^[（(]([一二三四五六七八九十]+)[）)]\s*(.*)$`)
	numHeadRe     = regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)*)\s+(\S.*)$`)
	vulnHeadRe    = regexp.MustCompile(`^漏洞\s*([0-9一二三四五六七八九十]+)\s*[:：]\s*(.*)$`)
	leadEnumRe    = regexp.MustCompile(`^(?:[一二三四五六七八九十百]+、|[（(][一二三四五六七八九十]+[）)]|\d+(?:\.\d+)*[、.．]?)\s*`)
	fenceBodyRe   = regexp.MustCompile("(?s)```[a-zA-Z0-9_-]*\\n(.*?)```")
	httpBlockRe   = regexp.MustCompile(`(?is)(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+\S+\s+HTTP/1\.[01][^\n]*(?:\n[^\n]+){0,40}`)
	remediationRe = regexp.MustCompile(`(?s)(?:^|\n)[ \t]*#{0,4}[ \t]*(?:修复建议|整改建议|防护建议|解决方案|加固建议)[ \t]*[:：]?[ \t]*\n?(.*)`)
	sevLabelRe    = regexp.MustCompile(`(?:风险等级|严重程度|危害等级)\s*[:：]\s*(严重|高危|中危|低危|critical|high|medium|low|info)`)
	bracketSevRe  = regexp.MustCompile(`(?i)\[(critical|high|medium|low|info|严重|高危|中危|低危)\]`)
	sevWordRe     = regexp.MustCompile(`严重|高危|中危|低危`)
	subItemRe     = regexp.MustCompile(`^(?:[A-Z]|[0-9]{1,2})[.、．]\s+\S`)
	newVulnMarkRe = regexp.MustCompile(`(?i)\[(critical|high|medium|low|严重|高危|中危|低危)\]`)
	taskLineRe    = regexp.MustCompile(`(?m)^[ \t]*[-*][ \t]*(?:\*\*)?所属任务(?:\*\*)?[^\n]*$`)
)

var noiseTitles = map[string]bool{
	"目录":       true,
	"保密声明":     true,
	"免责声明":     true,
	"文档修订记录":   true,
	"测试人员":     true,
	"评估范围":     true,
	"风险等级定义":   true,
	"概述":       true,
	"资产列表":     true,
	"评估概述":     true,
	"人员名单":     true,
	"声明":       true,
	"附录":       true,
	"漏洞发现汇总报告": true,
	"汇总报告":     true,
	"摘要":       true,
	"报告摘要":     true,
	"执行摘要":     true,
	"漏洞明细":     true,
	"发现明细":     true,
	"风险汇总":     true,
}

var vulnSubHeadings = map[string]bool{
	"概述": true, "漏洞概述": true, "漏洞描述": true, "问题描述": true,
	"影响与危害": true, "危害分析": true, "漏洞危害": true, "风险分析": true,
	"受影响范围": true, "影响范围": true, "受影响资产": true,
	"复现步骤": true, "漏洞复现": true, "测试步骤": true, "验证步骤": true, "攻击过程": true,
	"证据": true, "漏洞证据": true, "测试证据": true, "截图与证据": true,
	"poc": true, "exp": true, "验证脚本": true, "请求报文": true,
	"根因分析": true, "漏洞成因": true, "成因分析": true, "原理分析": true,
	"修复建议": true, "整改建议": true, "防护建议": true, "解决方案": true, "加固建议": true,
}

// SplitReportIntoChunks redacts the report, drops administrative chapters, and
// packs the rest into at most 8 chunks of maxChunkRunes. A non-positive limit
// uses 6000 runes.
func SplitReportIntoChunks(rawMD string, maxChunkRunes int) []string {
	if maxChunkRunes <= 0 {
		maxChunkRunes = defaultReportChunkRunes
	}
	text := redactReportText(rawMD)
	var pieces []string
	for _, sec := range splitReportSections(text) {
		if isNoiseTitle(sec.title) {
			continue
		}
		piece := strings.TrimSpace(sectionText(sec))
		if piece == "" {
			continue
		}
		pieces = append(pieces, piece)
	}
	var chunks []string
	var cur strings.Builder
	curRunes := 0
	flush := func() {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		curRunes = 0
		if s != "" && len(chunks) < maxReportChunks {
			chunks = append(chunks, s)
		}
	}
	for _, piece := range pieces {
		if len(chunks) >= maxReportChunks {
			break
		}
		parts := []string{piece}
		if utf8.RuneCountInString(piece) > maxChunkRunes {
			if curRunes > 0 {
				flush()
			}
			parts = splitOversized(piece, maxChunkRunes)
			for _, part := range parts {
				if len(chunks) >= maxReportChunks {
					break
				}
				chunks = append(chunks, part)
			}
			continue
		}
		n := utf8.RuneCountInString(piece)
		if curRunes > 0 && curRunes+2+n > maxChunkRunes {
			flush()
		}
		if len(chunks) >= maxReportChunks {
			break
		}
		if cur.Len() > 0 {
			cur.WriteString("\n\n")
			curRunes += 2
		}
		cur.WriteString(piece)
		curRunes += n
	}
	flush()
	return chunks
}

// redactReportText masks HTTP packets first, then hosts, IPs, and secrets.
// RedactSensitive writes URL hosts as <host>. This pipeline rewrites that to
// <target-host> so report drafts match the placeholder used in HTTP Host lines.
func redactReportText(s string) string {
	s = taskLineRe.ReplaceAllString(s, "")
	s = redactFencedHTTP(s)
	s = redactBareHTTP(s)
	s = RedactSensitive(s)
	s = strings.ReplaceAll(s, "<host>", "<target-host>")
	return s
}

func redactFencedHTTP(s string) string {
	return fenceBodyRe.ReplaceAllStringFunc(s, func(block string) string {
		m := fenceBodyRe.FindStringSubmatch(block)
		if len(m) < 2 || !looksLikeHTTP(m[1]) {
			return block
		}
		req, resp := splitReportHTTP(m[1])
		redReq, redResp := RedactHTTPPacket(req, resp)
		body := strings.TrimSpace(redReq)
		if strings.TrimSpace(redResp) != "" {
			if body != "" {
				body += "\n\n"
			}
			body += strings.TrimSpace(redResp)
		}
		return "```http\n" + body + "\n```"
	})
}

func looksLikeHTTP(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if httpStartLine.MatchString(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}

func redactBareHTTP(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	inFence := false
	for i := 0; i < len(lines); i++ {
		trim := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trim, "```") {
			inFence = !inFence
			out = append(out, lines[i])
			continue
		}
		if inFence || !httpStartLine.MatchString(trim) {
			out = append(out, lines[i])
			continue
		}
		end := i + 1
		for end < len(lines) {
			line := lines[end]
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "```") || httpStartLine.MatchString(t) {
				break
			}
			end++
		}
		if end < len(lines) && strings.TrimSpace(lines[end]) == "" {
			k := end + 1
			body := 0
			for k < len(lines) {
				t := strings.TrimSpace(lines[k])
				if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "```") || httpStartLine.MatchString(t) {
					break
				}
				body++
				k++
			}
			if body > 0 && body <= 40 {
				end = k
			}
		}
		block := strings.Join(lines[i:end], "\n")
		req, resp := splitReportHTTP(block)
		redReq, redResp := RedactHTTPPacket(req, resp)
		merged := strings.TrimSpace(redReq)
		if strings.TrimSpace(redResp) != "" {
			if merged != "" {
				merged += "\n\n"
			}
			merged += strings.TrimSpace(redResp)
		}
		out = append(out, merged)
		i = end - 1
	}
	return strings.Join(out, "\n")
}

func splitReportHTTP(block string) (req, resp string) {
	block = strings.TrimSpace(block)
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		if regexp.MustCompile(`(?i)^HTTP/1\.[01]\s+\d{3}`).MatchString(strings.TrimSpace(line)) && i > 0 {
			return strings.TrimSpace(strings.Join(lines[:i], "\n")), strings.TrimSpace(strings.Join(lines[i:], "\n"))
		}
	}
	return block, ""
}

type reportSection struct {
	title string
	body  string
}

func splitReportSections(md string) []reportSection {
	md = strings.ReplaceAll(md, "\r\n", "\n")
	lines := strings.Split(md, "\n")
	var sections []reportSection
	var title string
	var body []string
	inFence := false
	started := false
	inVuln := false
	flush := func() {
		sections = append(sections, reportSection{title: title, body: strings.TrimSpace(strings.Join(body, "\n"))})
	}
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "```") {
			inFence = !inFence
			body = append(body, line)
			continue
		}
		if !inFence {
			if t, level, ok := matchSectionHeading(line); ok {
				if inVuln && isSubSectionTitle(t, level) {
					body = append(body, "### "+t)
					continue
				}
				if started || strings.TrimSpace(strings.Join(body, "\n")) != "" {
					flush()
				}
				title = t
				body = nil
				started = true
				inVuln = !isNoiseTitle(t)
				continue
			}
		}
		body = append(body, line)
	}
	if started || strings.TrimSpace(strings.Join(body, "\n")) != "" {
		flush()
	}
	return sections
}

func matchSectionHeading(line string) (string, int, bool) {
	if m := mdHeadRe.FindStringSubmatch(line); m != nil {
		return strings.TrimSpace(m[2]), len(m[1]), true
	}
	trim := strings.TrimSpace(line)
	if m := cnOrdRe.FindStringSubmatch(trim); m != nil {
		if strings.TrimSpace(m[2]) == "" {
			return strings.TrimSpace(m[1]), 1, true
		}
		return strings.TrimSpace(m[2]), 1, true
	}
	if m := cnParenRe.FindStringSubmatch(trim); m != nil {
		if strings.TrimSpace(m[2]) == "" {
			return strings.TrimSpace(m[1]), 1, true
		}
		return strings.TrimSpace(m[2]), 1, true
	}
	if m := vulnHeadRe.FindStringSubmatch(trim); m != nil {
		if strings.TrimSpace(m[2]) == "" {
			return strings.TrimSpace(trim), 1, true
		}
		return strings.TrimSpace(m[2]), 1, true
	}
	if m := numHeadRe.FindStringSubmatch(trim); m != nil {
		return strings.TrimSpace(m[2]), 2, true
	}
	return "", 0, false
}

// isSubSectionTitle reports headings that belong inside the current vulnerability:
// named subsections such as 复现步骤, and deeper evidence items such as "### A. ..."
// or "### 1. 未授权签发". A heading that carries its own severity mark starts a new vulnerability.
func isSubSectionTitle(title string, level int) bool {
	if newVulnMarkRe.MatchString(title) {
		return false
	}
	if vulnSubHeadings[strings.ToLower(canonicalNoiseTitle(title))] {
		return true
	}
	return level >= 3 && subItemRe.MatchString(strings.TrimSpace(title))
}

func sectionText(sec reportSection) string {
	title := strings.TrimSpace(sec.title)
	body := strings.TrimSpace(sec.body)
	if title == "" {
		return body
	}
	if body == "" {
		return "# " + title
	}
	return "# " + title + "\n\n" + body
}

func isNoiseTitle(title string) bool {
	key := canonicalNoiseTitle(title)
	return key != "" && noiseTitles[key]
}

func canonicalNoiseTitle(title string) string {
	title = strings.TrimSpace(title)
	title = strings.TrimLeft(title, "#")
	title = strings.TrimSpace(title)
	title = strings.TrimSpace(leadEnumRe.ReplaceAllString(title, ""))
	return title
}

func splitOversized(piece string, max int) []string {
	if utf8.RuneCountInString(piece) <= max {
		return []string{strings.TrimSpace(piece)}
	}
	var paras []string
	for _, p := range strings.Split(piece, "\n\n") {
		p = strings.TrimSpace(p)
		if p != "" {
			paras = append(paras, p)
		}
	}
	var out []string
	var cur strings.Builder
	n := 0
	flush := func() {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		n = 0
		if s != "" {
			out = append(out, s)
		}
	}
	for _, p := range paras {
		pn := utf8.RuneCountInString(p)
		if pn > max {
			flush()
			rs := []rune(p)
			for len(rs) > 0 {
				take := max
				if take > len(rs) {
					take = len(rs)
				}
				out = append(out, string(rs[:take]))
				rs = rs[take:]
			}
			continue
		}
		if n > 0 && n+2+pn > max {
			flush()
		}
		if cur.Len() > 0 {
			cur.WriteString("\n\n")
			n += 2
		}
		cur.WriteString(p)
		n += pn
	}
	flush()
	return out
}

// ReportLLM completes one chat turn. A nil function, or a returned error, falls back per chunk.
type ReportLLM func(ctx context.Context, system, user string) (string, error)

// DistillReportChunks turns redacted chunks into candidate entries.
// usedLLM is true only when at least one chunk was parsed from the model.
// A failed chunk falls back on its own and does not fail the whole report.
// llmErr is empty when the model was not requested or at least the failures
// were not the reason for the draft. Callers show it when usedLLM is false.
func DistillReportChunks(ctx context.Context, chunks []string, useLLM bool, complete ReportLLM) ([]db.KBEntry, bool, string) {
	if len(chunks) == 0 {
		return nil, false, ""
	}
	if !useLLM {
		return DedupeReportEntries(FallbackExtractReportEntries(chunks)), false, ""
	}
	if complete == nil {
		return DedupeReportEntries(FallbackExtractReportEntries(chunks)), false, "当前未配置激活的 LLM 模型，已使用规则引擎按漏洞章节聚合提取"
	}
	var out []db.KBEntry
	var errs []string
	used := false
	note := func(err error) {
		if err == nil {
			return
		}
		msg := "LLM 调用失败或超时，已自动回退为规则提取: " + clipRunes(strings.Join(strings.Fields(err.Error()), " "), 240)
		for _, existing := range errs {
			if existing == msg {
				return
			}
		}
		errs = append(errs, msg)
	}
	for _, chunk := range chunks {
		if ctx.Err() != nil {
			note(ctx.Err())
			out = append(out, FallbackExtractReportEntries([]string{chunk})...)
			continue
		}
		raw, err := complete(ctx, DistillReportSystem, chunk)
		if err != nil {
			note(err)
			out = append(out, FallbackExtractReportEntries([]string{chunk})...)
			continue
		}
		fields, err := ParseDistillArrayJSON(raw)
		if err != nil || len(fields) == 0 {
			if err == nil {
				err = fmt.Errorf("没有可解析的知识条目")
			}
			note(err)
			out = append(out, FallbackExtractReportEntries([]string{chunk})...)
			continue
		}
		converted := fieldsToReportEntries(fields)
		if len(converted) == 0 {
			note(fmt.Errorf("没有可解析的知识条目"))
			out = append(out, FallbackExtractReportEntries([]string{chunk})...)
			continue
		}
		out = append(out, converted...)
		used = true
	}
	return DedupeReportEntries(out), used, strings.Join(errs, "；")
}

// ParseDistillArrayJSON accepts a JSON array or an object with an entries field.
func ParseDistillArrayJSON(raw string) ([]DistillFields, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSpace(stripCodeFence(raw))
	if i := strings.Index(raw, "["); i >= 0 {
		if j := strings.LastIndex(raw, "]"); j > i {
			var fields []DistillFields
			if json.Unmarshal([]byte(raw[i:j+1]), &fields) == nil && len(fields) > 0 {
				return fields, nil
			}
		}
	}
	if i := strings.Index(raw, "{"); i >= 0 {
		if j := strings.LastIndex(raw, "}"); j > i {
			payload := raw[i : j+1]
			var wrap struct {
				Entries []DistillFields `json:"entries"`
			}
			if json.Unmarshal([]byte(payload), &wrap) == nil && len(wrap.Entries) > 0 {
				return wrap.Entries, nil
			}
			var one DistillFields
			if json.Unmarshal([]byte(payload), &one) == nil && (strings.TrimSpace(one.Title) != "" || strings.TrimSpace(one.Summary) != "" || strings.TrimSpace(one.ExternalID) != "") {
				return []DistillFields{one}, nil
			}
		}
	}
	return nil, fmt.Errorf("没有可解析的知识条目")
}

func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```")
	if nl := strings.IndexByte(s, '\n'); nl >= 0 {
		s = s[nl+1:]
	}
	s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	return strings.TrimSpace(s)
}

func fieldsToReportEntries(fields []DistillFields) []db.KBEntry {
	var out []db.KBEntry
	for _, f := range fields {
		title := strings.TrimSpace(redactReportText(f.Title))
		summary := strings.TrimSpace(redactReportText(f.Summary))
		ext := strings.TrimSpace(f.ExternalID)
		if title == "" && summary == "" && ext == "" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(f.Kind))
		if !db.ValidKBKind(kind) {
			kind = "methodology"
		}
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if !db.ValidKBSeverity(sev) {
			sev = db.KBSevInfo
		}
		e := db.KBEntry{
			Title:            title,
			Kind:             kind,
			VulnClass:        strings.TrimSpace(f.VulnClass),
			Severity:         sev,
			Products:         db.NormalizeProducts(f.Products),
			Tags:             normalizeReportTags(f.Tags),
			AffectedVersions: strings.TrimSpace(f.AffectedVersions),
			ExternalID:       ext,
			Summary:          clipRunes(summary, 4000),
			DetectionGuide:   strings.TrimSpace(redactReportText(f.DetectionGuide)),
			PocSnippet:       strings.TrimSpace(redactReportText(f.PocSnippet)),
			Remediation:      strings.TrimSpace(redactReportText(f.Remediation)),
			Origin:           "manual",
			Distilled:        true,
			Enabled:          true,
		}
		e.HasPoC = strings.TrimSpace(e.PocSnippet) != ""
		if e.ExternalID != "" {
			e.NKey = db.CanonicalNKey(e.ExternalID, e.Kind, e.Title, "")
		}
		out = append(out, e)
	}
	return out
}

func normalizeReportTags(items []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range items {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// FallbackExtractReportEntries builds one entry per chapter when the model is off.
// Fenced blocks and raw HTTP requests become the PoC. Text after 修复建议 / 整改建议
// becomes the remediation. 严重 / 高危 / 中危 / 低危 map onto knowledge severities.
func FallbackExtractReportEntries(chunks []string) []db.KBEntry {
	var sections []reportSection
	for _, chunk := range chunks {
		sections = append(sections, splitReportSections(chunk)...)
	}
	var out []db.KBEntry
	for _, sec := range sections {
		if isNoiseTitle(sec.title) {
			continue
		}
		title := strings.TrimSpace(sec.title)
		body := strings.TrimSpace(sec.body)
		if isRemediationTitle(title) {
			if n := len(out); n > 0 && strings.TrimSpace(out[n-1].Remediation) == "" {
				out[n-1].Remediation = clipRunes(body, 8000)
			}
			continue
		}
		if title == "" && body == "" {
			continue
		}
		if title == "" {
			title = clipRunes(body, 80)
		}
		rem := extractRemediation(body)
		guide := extractDetectionGuide(body)
		poc := extractPoC(body)
		kind := "methodology"
		if poc != "" {
			kind = "poc"
		}
		if strings.Contains(title, "检查清单") || strings.Contains(strings.ToLower(title), "checklist") {
			kind = "checklist"
		}
		e := db.KBEntry{
			Title:          title,
			Summary:        extractSummary(body, rem),
			DetectionGuide: guide,
			PocSnippet:     poc,
			Remediation:    rem,
			Severity:       extractSeverity(title + "\n" + body),
			Kind:           kind,
			Origin:         "manual",
			Distilled:      true,
			Enabled:        true,
			HasPoC:         poc != "",
		}
		out = append(out, e)
	}
	return out
}

func isRemediationTitle(title string) bool {
	switch canonicalNoiseTitle(title) {
	case "修复建议", "整改建议":
		return true
	default:
		return false
	}
}

func extractPoC(body string) string {
	var parts []string
	for _, m := range fenceBodyRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 && strings.TrimSpace(m[1]) != "" {
			parts = append(parts, strings.TrimSpace(m[1]))
		}
	}
	if len(parts) == 0 {
		if m := httpBlockRe.FindString(body); strings.TrimSpace(m) != "" {
			parts = append(parts, strings.TrimSpace(m))
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n\n"))
}

func extractRemediation(body string) string {
	m := remediationRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	text := strings.TrimSpace(m[1])
	if i := strings.Index(text, "\n#"); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	return clipRunes(text, 8000)
}

func extractSummary(body, remediation string) string {
	for _, name := range []string{"概述", "漏洞概述", "漏洞描述", "问题描述"} {
		if text := blockText(body, name); text != "" {
			return clipRunes(firstParagraph(text), 400)
		}
	}
	preamble := body
	if i := strings.Index(preamble, "\n### "); i >= 0 {
		preamble = preamble[:i]
	}
	preamble = firstParagraph(strings.TrimSpace(preamble))
	if preamble == "" {
		preamble = firstParagraph(firstProse(body, remediation))
	}
	return clipRunes(preamble, 400)
}

func extractDetectionGuide(body string) string {
	var parts []string
	for _, name := range []string{"复现步骤", "漏洞复现", "测试步骤", "验证步骤", "攻击过程", "根因分析", "漏洞成因", "成因分析", "原理分析"} {
		if text := blockText(body, name); text != "" {
			parts = append(parts, text)
		}
	}
	if len(parts) > 0 {
		return clipRunes(strings.TrimSpace(strings.Join(parts, "\n\n")), 20000)
	}
	text := body
	if i := strings.Index(text, "```"); i >= 0 {
		text = text[:i]
	}
	if i := strings.Index(text, "修复建议"); i >= 0 {
		text = text[:i]
	}
	return clipRunes(strings.TrimSpace(text), 20000)
}

func blockText(body, name string) string {
	lines := strings.Split(body, "\n")
	var buf []string
	capturing := false
	for _, line := range lines {
		if t, _, ok := matchSectionHeading(line); ok && vulnSubHeadings[strings.ToLower(canonicalNoiseTitle(t))] {
			if capturing {
				break
			}
			if canonicalNoiseTitle(t) == name {
				capturing = true
			}
			continue
		}
		if capturing {
			buf = append(buf, line)
		}
	}
	return strings.TrimSpace(strings.Join(buf, "\n"))
}

func firstParagraph(text string) string {
	text = strings.TrimSpace(text)
	if i := strings.Index(text, "\n\n"); i >= 0 {
		return strings.TrimSpace(text[:i])
	}
	return text
}

func extractSeverity(text string) string {
	if m := bracketSevRe.FindStringSubmatch(text); len(m) == 2 {
		return mapSeverityWord(m[1])
	}
	if m := sevLabelRe.FindStringSubmatch(text); len(m) == 2 {
		return mapSeverityWord(m[1])
	}
	cleaned := strings.ReplaceAll(text, "严重程度", "")
	cleaned = strings.ReplaceAll(cleaned, "风险等级", "")
	if m := sevWordRe.FindString(cleaned); m != "" {
		return mapSeverityWord(m)
	}
	lower := strings.ToLower(text)
	for _, word := range []string{"critical", "high", "medium", "low", "info"} {
		if strings.Contains(lower, word) {
			return word
		}
	}
	return db.KBSevInfo
}

func mapSeverityWord(word string) string {
	switch strings.ToLower(strings.TrimSpace(word)) {
	case "严重", "critical":
		return db.KBSevCritical
	case "高危", "high":
		return db.KBSevHigh
	case "中危", "medium":
		return db.KBSevMedium
	case "低危", "low":
		return db.KBSevLow
	case "info":
		return db.KBSevInfo
	default:
		return db.KBSevInfo
	}
}

func firstProse(body, remediation string) string {
	text := body
	if i := strings.Index(text, "```"); i >= 0 {
		text = text[:i]
	}
	if remediation != "" {
		if i := strings.Index(text, "修复建议"); i >= 0 {
			text = text[:i]
		}
		if i := strings.Index(text, "整改建议"); i >= 0 {
			text = text[:i]
		}
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return strings.TrimSpace(body)
	}
	return text
}

// DedupeReportEntries merges rows that share an external id or a similar title.
func DedupeReportEntries(in []db.KBEntry) []db.KBEntry {
	var out []db.KBEntry
	extAt := map[string]int{}
	titleAt := map[string]int{}
	for _, e := range in {
		ext := strings.ToUpper(strings.TrimSpace(e.ExternalID))
		key := titleKey(e.Title)
		if ext != "" {
			if i, ok := extAt[ext]; ok {
				out[i] = mergeReportEntry(out[i], e)
				continue
			}
		}
		if key != "" {
			if i, ok := titleAt[key]; ok {
				out[i] = mergeReportEntry(out[i], e)
				continue
			}
			if i, ok := similarTitle(titleAt, key); ok {
				out[i] = mergeReportEntry(out[i], e)
				if ext != "" {
					extAt[ext] = i
				}
				continue
			}
		}
		out = append(out, e)
		idx := len(out) - 1
		if ext != "" {
			extAt[ext] = idx
		}
		if key != "" {
			titleAt[key] = idx
		}
	}
	return out
}

func similarTitle(titleAt map[string]int, key string) (int, bool) {
	if utf8.RuneCountInString(key) < 10 {
		return 0, false
	}
	for existing, idx := range titleAt {
		if utf8.RuneCountInString(existing) < 10 {
			continue
		}
		short, long := key, existing
		if len(short) > len(long) {
			short, long = long, short
		}
		if strings.Contains(long, short) && float64(utf8.RuneCountInString(short))/float64(utf8.RuneCountInString(long)) >= 0.75 {
			return idx, true
		}
	}
	return 0, false
}

func titleKey(title string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(title)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func mergeReportEntry(a, b db.KBEntry) db.KBEntry {
	if strings.TrimSpace(a.Title) == "" {
		a.Title = b.Title
	}
	if strings.TrimSpace(a.Summary) == "" {
		a.Summary = b.Summary
	}
	if strings.TrimSpace(a.DetectionGuide) == "" {
		a.DetectionGuide = b.DetectionGuide
	}
	if strings.TrimSpace(a.PocSnippet) == "" {
		a.PocSnippet = b.PocSnippet
	}
	if strings.TrimSpace(a.Remediation) == "" {
		a.Remediation = b.Remediation
	}
	if strings.TrimSpace(a.ExternalID) == "" {
		a.ExternalID = b.ExternalID
	}
	if strings.TrimSpace(a.VulnClass) == "" {
		a.VulnClass = b.VulnClass
	}
	if strings.TrimSpace(a.AffectedVersions) == "" {
		a.AffectedVersions = b.AffectedVersions
	}
	if db.KBSeverityRank(b.Severity) > db.KBSeverityRank(a.Severity) {
		a.Severity = b.Severity
	}
	a.Products = db.NormalizeProducts(append(append([]string{}, a.Products...), b.Products...))
	a.Tags = normalizeReportTags(append(append([]string{}, a.Tags...), b.Tags...))
	if a.Kind == "" {
		a.Kind = b.Kind
	}
	a.Distilled = a.Distilled || b.Distilled
	a.Enabled = true
	if a.Origin == "" {
		a.Origin = "manual"
	}
	if strings.TrimSpace(a.ExternalID) != "" {
		a.NKey = db.CanonicalNKey(a.ExternalID, a.Kind, a.Title, a.NKey)
	} else if a.NKey == "" {
		a.NKey = b.NKey
	}
	return a
}

// ParseReportJSONEntries accepts an uploaded JSON array of knowledge entries.
func ParseReportJSONEntries(raw string) ([]db.KBEntry, bool) {
	raw = strings.TrimSpace(raw)
	var list []db.KBEntry
	if json.Unmarshal([]byte(raw), &list) != nil || len(list) == 0 {
		return nil, false
	}
	ok := false
	for i := range list {
		if strings.TrimSpace(list[i].Title) == "" && strings.TrimSpace(list[i].ExternalID) == "" {
			continue
		}
		ok = true
		if strings.TrimSpace(list[i].Origin) == "" {
			list[i].Origin = "manual"
		}
		if strings.TrimSpace(list[i].Kind) == "" {
			list[i].Kind = "methodology"
		}
		list[i].Products = db.NormalizeProducts(list[i].Products)
		list[i].Tags = normalizeReportTags(list[i].Tags)
		list[i].Enabled = true
		if strings.TrimSpace(list[i].ExternalID) != "" {
			list[i].NKey = db.CanonicalNKey(list[i].ExternalID, list[i].Kind, list[i].Title, list[i].NKey)
		}
	}
	if !ok {
		return nil, false
	}
	return list, true
}
