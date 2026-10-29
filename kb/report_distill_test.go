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
	entries, used := DistillReportChunks(context.Background(), []string{chunk}, true, func(ctx context.Context, system, user string) (string, error) {
		if system != DistillReportSystem {
			t.Fatalf("unexpected system prompt")
		}
		if !strings.Contains(user, "heapdump") {
			t.Fatalf("chunk not passed")
		}
		return raw, nil
	})
	if !used {
		t.Fatal("expected llm")
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

	fb, used := DistillReportChunks(context.Background(), []string{chunk}, false, nil)
	if used {
		t.Fatal("llm used while disabled")
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

	off, used := DistillReportChunks(context.Background(), []string{chunk}, true, func(ctx context.Context, system, user string) (string, error) {
		return "", errString("LLM 未配置")
	})
	if used || len(off) != 1 || off[0].Severity != "high" {
		t.Fatalf("error fallback used=%v len=%d", used, len(off))
	}
}

type errString string

func (e errString) Error() string { return string(e) }
