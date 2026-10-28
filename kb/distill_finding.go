package kb

import (
	"context"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// TrafficSample is one redacted request/response pair attached to a finding.
type TrafficSample struct {
	Method         string `json:"method"`
	URL            string `json:"url"`
	RequestRaw     string `json:"request_raw"`
	ResponseStatus int    `json:"response_status"`
	ResponseRaw    string `json:"response_raw"`
}

// DistillTarget is the knowledge row a finding may enrich.
type DistillTarget struct {
	ID    int64  `json:"id"`
	NKey  string `json:"nkey"`
	Title string `json:"title"`
	Kind  string `json:"kind"`
}

// FindingDistillInput is the redacted material for one finding.
type FindingDistillInput struct {
	FindingID      int64           `json:"finding_id"`
	Name           string          `json:"name"`
	VulnClass      string          `json:"vulnclass"`
	Severity       string          `json:"severity"`
	Summary        string          `json:"summary"`
	Evidence       string          `json:"evidence"`
	Report         string          `json:"report,omitempty"`
	AssetProducts  []string        `json:"asset_products"`
	TrafficSamples []TrafficSample `json:"traffic_samples"`
	ExistingKB     *DistillTarget  `json:"existing_kb,omitempty"`
	ExtraNotes     string          `json:"extra_notes,omitempty"`
}

const DistillFindingSystem = `你是授权安全评估的知识整理助手。根据一次已确认的实战发现，整理成可复用的检测知识，帮助测试人员在同类组件上判断是否需要验证。
只输出一个 JSON 对象，不要 Markdown。字段：
{"title":"面向同类组件的条目标题","kind":"poc|methodology|checklist","vulnclass":"漏洞类别","severity":"critical|high|medium|low|info","products":["归一化产品"],"tags":["小写标签"],"summary":"一两句公开摘要","detection_guide":"同类场景下看什么、如何对照版本与绕过前提，不要写目标专属主机","poc_snippet":"无害化验证请求模板，主机用 <target-host>","remediation":"可落地的修复建议","suggested_mode":"enrich_existing|new_entry"}
规则：
- 把这一次目标上的发现泛化成同类组件、同类接口形态可复用的探测指南。
- 抹掉具体域名、IP、账号、口令、Cookie、邮箱、手机号。路径、参数名、绕过变形和版本判断依据保留。
- 材料里没有的利用步骤不要编造。没有流量时 poc_snippet 可以为空，kind 用 methodology。
- 若材料给出了已关联的知识条目，且这次内容是对该条目的实战 PoC 或绕过补充，suggested_mode 用 enrich_existing；否则用 new_entry。`

// DistillFinding asks the model for a structured draft and falls back to a
// deterministic draft when the model is missing or unusable. in must already
// be redacted.
func DistillFinding(ctx context.Context, in FindingDistillInput, complete func(context.Context, string, string) (string, error)) DistillFields {
	fallback := BuildFallbackDistillFields(in)
	if complete == nil {
		return fallback
	}
	text, err := complete(ctx, DistillFindingSystem, distillUserPrompt(in))
	if err != nil || strings.TrimSpace(text) == "" {
		return fallback
	}
	fields, err := ParseDistillJSON(text)
	if err != nil || (strings.TrimSpace(fields.Title) == "" && strings.TrimSpace(fields.Summary) == "" && strings.TrimSpace(fields.DetectionGuide) == "") {
		return fallback
	}
	return mergeDistillFields(fallback, fields)
}

// BuildFallbackDistillFields assembles a draft without a model so distillation
// still works offline.
func BuildFallbackDistillFields(in FindingDistillInput) DistillFields {
	title := strings.TrimSpace(in.Name)
	if title == "" {
		title = strings.TrimSpace(in.VulnClass)
	}
	if title == "" {
		title = fmt.Sprintf("漏洞 #%d", in.FindingID)
	}
	kind := "methodology"
	var snippets []string
	for _, sample := range in.TrafficSamples {
		req, resp := RedactHTTPPacket(sample.RequestRaw, sample.ResponseRaw)
		if s := FormatPoCSnippet(req, resp); s != "" {
			snippets = append(snippets, s)
		}
	}
	poc := strings.Join(snippets, "\n\n")
	if poc != "" {
		kind = "poc"
	}
	sev := strings.ToLower(strings.TrimSpace(in.Severity))
	if !db.ValidKBSeverity(sev) {
		sev = db.KBSevInfo
	}
	guide := strings.TrimSpace(in.Evidence)
	if guide == "" {
		guide = strings.TrimSpace(in.Summary)
	}
	guide = "来自已登记漏洞的沉淀。下面是脱敏后的证据，只作为后续检测线索，不能代替在新目标上的再次触发。\n\n" + guide
	if notes := strings.TrimSpace(in.ExtraNotes); notes != "" {
		guide += "\n\n补充说明：\n" + notes
	}
	mode := "new_entry"
	if in.ExistingKB != nil && in.ExistingKB.ID > 0 {
		mode = "enrich_existing"
	}
	var tags []string
	if v := strings.ToLower(strings.TrimSpace(in.VulnClass)); v != "" {
		tags = []string{v}
	}
	remediation := ""
	if notes := strings.TrimSpace(in.ExtraNotes); strings.Contains(notes, "修复") {
		remediation = notes
	}
	return DistillFields{
		Title:          title,
		Kind:           kind,
		VulnClass:      strings.TrimSpace(in.VulnClass),
		Severity:       sev,
		Products:       db.NormalizeProducts(in.AssetProducts),
		Tags:           tags,
		Summary:        clipRunes(strings.TrimSpace(in.Summary), 500),
		DetectionGuide: clipRunes(guide, 8000),
		PocSnippet:     clipRunes(poc, 8000),
		Remediation:    clipRunes(remediation, 2000),
		SuggestedMode:  mode,
	}
}

func mergeDistillFields(base, model DistillFields) DistillFields {
	out := base
	if s := strings.TrimSpace(model.Title); s != "" {
		out.Title = s
	}
	if s := strings.TrimSpace(model.Kind); s == "poc" || s == "methodology" || s == "checklist" {
		out.Kind = s
	}
	if s := strings.TrimSpace(model.VulnClass); s != "" {
		out.VulnClass = s
	}
	if s := strings.ToLower(strings.TrimSpace(model.Severity)); db.ValidKBSeverity(s) {
		out.Severity = s
	}
	if s := strings.TrimSpace(model.Summary); s != "" {
		out.Summary = s
	}
	if s := strings.TrimSpace(model.DetectionGuide); s != "" {
		out.DetectionGuide = s
	}
	if s := strings.TrimSpace(model.PocSnippet); s != "" {
		out.PocSnippet = s
	}
	if s := strings.TrimSpace(model.Remediation); s != "" {
		out.Remediation = s
	}
	if len(model.Products) > 0 {
		out.Products = db.NormalizeProducts(append(append([]string{}, base.Products...), model.Products...))
	}
	if len(model.Tags) > 0 {
		out.Tags = append(out.Tags, model.Tags...)
	}
	switch strings.TrimSpace(model.SuggestedMode) {
	case "enrich_existing", "new_entry":
		out.SuggestedMode = model.SuggestedMode
	}
	if out.SuggestedMode == "enrich_existing" && (base.SuggestedMode != "enrich_existing") {
		out.SuggestedMode = "new_entry"
	}
	return out
}

func distillUserPrompt(in FindingDistillInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "漏洞 #%d\n名称: %s\n类别: %s\n等级: %s\n摘要: %s\n", in.FindingID, in.Name, in.VulnClass, in.Severity, in.Summary)
	if len(in.AssetProducts) > 0 {
		fmt.Fprintf(&b, "资产组件: %s\n", strings.Join(in.AssetProducts, ", "))
	}
	if in.ExistingKB != nil && in.ExistingKB.ID > 0 {
		fmt.Fprintf(&b, "已关联知识条目 #%d（%s）%s [%s]。若本次只是补充该条目的实战验证，suggested_mode 用 enrich_existing。\n", in.ExistingKB.ID, in.ExistingKB.NKey, in.ExistingKB.Title, in.ExistingKB.Kind)
	}
	if in.Evidence != "" {
		fmt.Fprintf(&b, "\n证据:\n%s\n", clipRunes(in.Evidence, 4000))
	}
	if in.Report != "" {
		fmt.Fprintf(&b, "\n报告摘录:\n%s\n", clipRunes(in.Report, 4000))
	}
	for i, sample := range in.TrafficSamples {
		fmt.Fprintf(&b, "\n流量 %d %s %s -> %d\n%s\n", i+1, sample.Method, sample.URL, sample.ResponseStatus, clipRunes(FormatPoCSnippet(sample.RequestRaw, sample.ResponseRaw), 2500))
	}
	if notes := strings.TrimSpace(in.ExtraNotes); notes != "" {
		fmt.Fprintf(&b, "\n补充说明:\n%s\n", notes)
	}
	return b.String()
}

func clipRunes(s string, n int) string {
	s = strings.TrimSpace(s)
	rs := []rune(s)
	if n <= 0 || len(rs) <= n {
		return s
	}
	return string(rs[:n])
}
