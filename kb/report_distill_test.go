package kb

import (
	"context"
	"strings"
	"testing"
)

func TestSplitReportIntoChunks(t *testing.T) {
	raw := `# 目录

- 仅目录条目

# 保密声明

本文保密，不得外传。

# 概述

这是行政概述。

# 漏洞概述

本节必须保留。

# SQL 注入

登录地址 https://oa.corp-internal.com/login ，数据库 10.20.30.40。

POST /login HTTP/1.1
Host: oa.corp-internal.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret
`
	chunks := SplitReportIntoChunks(raw, 6000)
	joined := strings.Join(chunks, "\n")
	for _, gone := range []string{"仅目录条目", "本文保密", "这是行政概述", "oa.corp-internal.com", "10.20.30.40"} {
		if strings.Contains(joined, gone) {
			t.Fatalf("kept %q\n%s", gone, joined)
		}
	}
	if !strings.Contains(joined, "<target-host>") {
		t.Fatalf("host placeholder missing:\n%s", joined)
	}
	if !strings.Contains(joined, "<ip>") {
		t.Fatalf("ip placeholder missing:\n%s", joined)
	}
	if !strings.Contains(joined, "本节必须保留") || !strings.Contains(joined, "漏洞概述") {
		t.Fatalf("technical section dropped:\n%s", joined)
	}
	if strings.Contains(joined, "password=secret") {
		t.Fatalf("password kept:\n%s", joined)
	}
}

func TestDistillReportChunk_LLMAndFallback(t *testing.T) {
	chunk := `# Spring Boot Actuator 未授权访问

风险等级：高危

GET /actuator/heapdump HTTP/1.1
Host: app.internal

修复建议
关闭 heapdump 端点并加上鉴权。
`
	raw := `[
	  {"title":"Spring Boot Actuator Heapdump 信息泄露","kind":"methodology","vulnclass":"info_leak","severity":"high","products":["Spring Boot"],"tags":["Actuator","Heapdump"],"summary":"未授权可下载 heapdump","detection_guide":"请求 /actuator/heapdump","poc_snippet":"GET /actuator/heapdump HTTP/1.1\nHost: <target-host>","remediation":"关闭 heapdump","external_id":"CVE-2024-12345"},
	  {"title":"另一个标题","kind":"poc","severity":"critical","products":["Apache Tomcat"],"tags":["Tomcat"],"summary":"同一 CVE","poc_snippet":"GET /x HTTP/1.1","external_id":"CVE-2024-12345"}
	]`
	entries, used, llmErr := DistillReportChunks(context.Background(), []string{chunk}, true, func(ctx context.Context, system, user string) (string, error) {
		if system != DistillReportSystem {
			t.Fatalf("unexpected system prompt")
		}
		if !strings.Contains(user, "heapdump") {
			t.Fatalf("chunk not passed")
		}
		return raw, nil
	})
	if !used || llmErr != "" {
		t.Fatalf("expected llm, err=%q", llmErr)
	}
	if len(entries) != 1 {
		t.Fatalf("dedupe len %d", len(entries))
	}
	e := entries[0]
	if len(e.Products) < 2 || e.Products[0] != "spring-boot" || e.Products[1] != "tomcat" {
		t.Fatalf("products %#v", e.Products)
	}
	if e.NKey != "cve:CVE-2024-12345" {
		t.Fatalf("nkey %s", e.NKey)
	}
	if e.Origin != "manual" || !e.Distilled {
		t.Fatalf("origin/distilled %+v", e)
	}
	if e.Severity != "critical" {
		t.Fatalf("severity %s", e.Severity)
	}
	foundTag := false
	for _, tag := range e.Tags {
		if tag == "actuator" {
			foundTag = true
		}
	}
	if !foundTag {
		t.Fatalf("tags %#v", e.Tags)
	}

	wrapped, err := ParseDistillArrayJSON("```json\n{\"entries\":[{\"title\":\"检查清单\",\"kind\":\"checklist\",\"summary\":\"s\"}]}\n```")
	if err != nil || len(wrapped) != 1 || wrapped[0].Kind != "checklist" {
		t.Fatalf("wrapped parse %+v %v", wrapped, err)
	}

	fb, used, llmErr := DistillReportChunks(context.Background(), []string{chunk}, false, nil)
	if used || llmErr != "" {
		t.Fatalf("llm used while disabled err=%q", llmErr)
	}
	if len(fb) != 1 {
		t.Fatalf("fallback len %d", len(fb))
	}
	if fb[0].Severity != "high" {
		t.Fatalf("fallback severity %s", fb[0].Severity)
	}
	if !strings.Contains(fb[0].PocSnippet, "heapdump") {
		t.Fatalf("fallback poc %q", fb[0].PocSnippet)
	}
	if !strings.Contains(fb[0].Remediation, "关闭 heapdump") {
		t.Fatalf("fallback remediation %q", fb[0].Remediation)
	}
	if !strings.Contains(fb[0].Title, "Spring Boot Actuator") {
		t.Fatalf("fallback title %q", fb[0].Title)
	}

	off, used, llmErr := DistillReportChunks(context.Background(), []string{chunk}, true, func(ctx context.Context, system, user string) (string, error) {
		return "", errString("LLM 未配置")
	})
	if used || len(off) != 1 || off[0].Severity != "high" || !strings.Contains(llmErr, "LLM 未配置") {
		t.Fatalf("error fallback used=%v len=%d err=%q", used, len(off), llmErr)
	}

	none, used, llmErr := DistillReportChunks(context.Background(), []string{chunk}, true, nil)
	if used || len(none) != 1 || !strings.Contains(llmErr, "未配置激活的 LLM") {
		t.Fatalf("nil llm used=%v len=%d err=%q", used, len(none), llmErr)
	}
}

func TestDistillRealWorldFindingReport(t *testing.T) {
	raw := strings.Join([]string{
		"# 漏洞发现汇总报告",
		"",
		"- **所属任务**：通过 socks5h://host.docker.internal:7890 访问内网，禁止扩大范围",
		"",
		"## 摘要",
		"",
		"这是汇总，不应单独成条。",
		"",
		"## 漏洞明细",
		"",
		"### 1. [CRITICAL] unify_users 会话刷新接口未授权签发 Session",
		"",
		"organ_simple_name=浙江省肿瘤医院",
		`user_name="陈承坤"`,
		"钉钉 ding5ac93f66828c8f3835c2f4657eb6378f",
		"AK LTAIk86eVH7vSshO",
		"来源 111.2.75.206",
		"跳板 host.docker.internal",
		"",
		"## 影响与危害",
		"",
		"1. **完全绕过认证**：未授权签发 session",
		"2. 持 session 拉全量职工",
		"",
		"## 受影响范围",
		"",
		"浙江省肿瘤医院 的 GooCan HRM。",
		"",
		"## 复现步骤",
		"",
		"### 1. 未授权签发 session",
		"",
		"直接请求刷新接口。",
		"",
		"### 2. 持 session 拉全量职工",
		"",
		"用返回的 session 继续请求职工列表。",
		"",
		"## 证据",
		"",
		"### A. 未授权 refresh 成功",
		"",
		"响应包含 session。",
		"",
		"### B. 职工列表",
		"",
		"返回职工数据。",
		"",
		"## PoC",
		"",
		"```http",
		"POST /unify_users/user/session/info/refresh HTTP/1.1",
		"Host: hr.internal.example",
		"```",
		"",
		"## 根因分析",
		"",
		"刷新接口未校验登录态，可被同类系统复用排查。",
		"",
		"## 修复建议",
		"",
		"刷新接口必须校验已登录会话，禁止未授权签发。",
		"",
	}, "\n")

	chunks := SplitReportIntoChunks(raw, 6000)
	entries := FallbackExtractReportEntries(chunks)
	if len(entries) != 1 {
		var titles []string
		for _, e := range entries {
			titles = append(titles, e.Title)
		}
		t.Fatalf("entries=%d titles=%v chunks=%d", len(entries), titles, len(chunks))
	}
	e := entries[0]
	blob := e.Title + "\n" + e.Summary + "\n" + e.DetectionGuide + "\n" + e.PocSnippet + "\n" + e.Remediation
	for _, leaked := range []string{"浙江省肿瘤医院", "陈承坤", "ding5ac93f66828c8f3835c2f4657eb6378f", "LTAIk86eVH7vSshO", "111.2.75.206", "host.docker.internal", "这是汇总"} {
		if strings.Contains(blob, leaked) {
			t.Fatalf("leaked %q\n%s", leaked, blob)
		}
	}
	if e.Severity != "critical" || e.Kind != "poc" || !e.HasPoC {
		t.Fatalf("identity severity=%s kind=%s poc=%v", e.Severity, e.Kind, e.HasPoC)
	}
	if !strings.Contains(e.PocSnippet, "/unify_users/user/session/info/refresh") || strings.Contains(e.PocSnippet, "hr.internal.example") {
		t.Fatalf("poc %q", e.PocSnippet)
	}
	if !strings.Contains(e.Remediation, "禁止未授权签发") {
		t.Fatalf("remediation %q", e.Remediation)
	}
	if !strings.Contains(e.DetectionGuide, "未校验登录态") || !strings.Contains(e.DetectionGuide, "未授权签发 session") {
		t.Fatalf("guide %q", e.DetectionGuide)
	}
	if strings.Contains(e.Summary, "完全绕过认证") || strings.Contains(e.Summary, "###") {
		t.Fatalf("summary swallowed later sections: %q", e.Summary)
	}

	model := `[{"title":"GooCan HRM unify_users 未授权签发 Session PoC","kind":"poc","severity":"critical","products":["Spring Boot"],"tags":["session-refresh"],"summary":"刷新接口未登录即可签发","detection_guide":"识别 unify_users 刷新接口并做未登录对照","poc_snippet":"POST /unify_users/user/session/info/refresh HTTP/1.1\nHost: <target-host>","remediation":"校验登录态"},{"title":"会话刷新接口未授权签发的通用排查","kind":"methodology","severity":"high","products":["Apache Tomcat"],"summary":"刷新类接口常缺少登录校验","detection_guide":"对刷新、换票、保活接口做未登录与过期会话对照","poc_snippet":"","remediation":"统一在网关校验会话"}]`
	got, used, llmErr := DistillReportChunks(context.Background(), chunks, true, func(ctx context.Context, system, user string) (string, error) {
		if system != DistillReportSystem || !strings.Contains(user, "unify_users") {
			t.Fatalf("prompt or chunk missing")
		}
		return model, nil
	})
	if !used || llmErr != "" || len(got) != 2 {
		t.Fatalf("llm used=%v err=%q len=%d", used, llmErr, len(got))
	}
	if got[0].Kind != "poc" || !got[0].HasPoC || !strings.Contains(got[0].PocSnippet, "/unify_users/user/session/info/refresh") {
		t.Fatalf("poc entry %+v", got[0])
	}
	if len(got[0].Products) != 1 || got[0].Products[0] != "spring-boot" {
		t.Fatalf("poc products %#v", got[0].Products)
	}
	if got[1].Kind != "methodology" || got[1].DetectionGuide == "" || len(got[1].Products) != 1 || got[1].Products[0] != "tomcat" {
		t.Fatalf("method entry %+v", got[1])
	}
}

type errString string

func (e errString) Error() string { return string(e) }
