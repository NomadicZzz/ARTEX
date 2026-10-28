package kb

import (
	"strings"
	"testing"
)

func TestRedactHTTPPacket(t *testing.T) {
	req := strings.Join([]string{
		"POST https://secret.internal/api/v1/user/import?x=1 HTTP/1.1",
		"Host: 10.1.2.3",
		"Cookie: session=abc",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
		"X-Api-Key: real-key",
		"Content-Type: application/json",
		"",
		`{"password":"p@ss","host":"192.168.1.5","email":"a@b.com","phone":"13800138000"}`,
	}, "\n")
	noneHeader := "eyJhbGciOiJub25lIn0"
	reqNone := "GET /admin HTTP/1.1\nAuthorization: Bearer " + noneHeader + ".eyJzdWIiOiIxIn0.\nHost: vpn.corp\n"
	resp := strings.Join([]string{
		"HTTP/1.1 200 OK",
		"Server: nginx",
		"Set-Cookie: sid=secret",
		"Content-Type: text/plain",
		"X-Internal: 10.8.8.8",
		"",
		"uid=0(root) at 192.168.0.9",
	}, "\n")

	gotReq, gotResp := RedactHTTPPacket(req, resp)
	for _, leak := range []string{"secret.internal", "10.1.2.3", "session=abc", "real-key", "p@ss", "192.168.1.5", "a@b.com", "13800138000", "eyJhbGciOiJIUzI1NiJ9"} {
		if strings.Contains(gotReq, leak) {
			t.Fatalf("request still has %q\n%s", leak, gotReq)
		}
	}
	if !strings.Contains(gotReq, "POST https://<target-host>/api/v1/user/import?x=1 HTTP/1.1") {
		t.Fatalf("path lost: %s", gotReq)
	}
	if !strings.Contains(gotReq, "Host: <target-host>") || !strings.Contains(gotReq, "Content-Type: application/json") {
		t.Fatalf("headers: %s", gotReq)
	}
	if !strings.Contains(gotReq, "<ip>") || !strings.Contains(gotReq, "<email>") || !strings.Contains(gotReq, "<phone>") {
		t.Fatalf("body placeholders: %s", gotReq)
	}

	gotNone, _ := RedactHTTPPacket(reqNone, "")
	if !strings.Contains(gotNone, noneHeader+".<redacted>.<redacted>") {
		t.Fatalf("alg=none structure lost: %s", gotNone)
	}
	if strings.Contains(gotNone, "vpn.corp") {
		t.Fatalf("host leaked: %s", gotNone)
	}

	for _, leak := range []string{"sid=secret", "10.8.8.8", "192.168.0.9"} {
		if strings.Contains(gotResp, leak) {
			t.Fatalf("response still has %q\n%s", leak, gotResp)
		}
	}
	if !strings.Contains(gotResp, "HTTP/1.1 200 OK") || !strings.Contains(gotResp, "Server: nginx") || !strings.Contains(gotResp, "uid=0(root)") {
		t.Fatalf("indicator lost: %s", gotResp)
	}
	if !strings.Contains(gotResp, "Set-Cookie: <redacted>") {
		t.Fatalf("cookie not redacted: %s", gotResp)
	}
}

func TestRedactSensitiveIPv6AndKeepsPlaceholder(t *testing.T) {
	got := RedactSensitive("see https://<target-host>/a and 2001:db8::1 and 12:30:00")
	if strings.Contains(got, "2001:db8") {
		t.Fatalf("ipv6 leaked: %s", got)
	}
	if !strings.Contains(got, "https://<target-host>/a") || !strings.Contains(got, "12:30:00") {
		t.Fatalf("placeholder or clock changed: %s", got)
	}
}

func TestBuildFallbackDistillFields(t *testing.T) {
	in := FindingDistillInput{
		FindingID: 7, Name: "未授权上传", VulnClass: "upload", Severity: "high",
		Summary: "任意文件上传", Evidence: "POST /upload 返回路径",
		AssetProducts: []string{"Apache Tomcat"},
		TrafficSamples: []TrafficSample{{
			RequestRaw:  "POST /upload HTTP/1.1\nHost: a.example\n\nfile=1",
			ResponseRaw: "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nok",
		}},
		ExistingKB: &DistillTarget{ID: 3, NKey: "cve:CVE-2024-1", Title: "已有条目", Kind: "cve"},
	}
	got := BuildFallbackDistillFields(in)
	if got.Kind != "poc" || got.SuggestedMode != "enrich_existing" {
		t.Fatalf("kind/mode = %s %s", got.Kind, got.SuggestedMode)
	}
	if len(got.Products) != 1 || got.Products[0] != "tomcat" {
		t.Fatalf("products = %#v", got.Products)
	}
	if !strings.Contains(got.PocSnippet, "Host: <target-host>") || strings.Contains(got.PocSnippet, "a.example") {
		t.Fatalf("poc = %s", got.PocSnippet)
	}
	if !strings.Contains(got.DetectionGuide, "POST /upload") {
		t.Fatalf("guide = %s", got.DetectionGuide)
	}

	offline := DistillFinding(t.Context(), FindingDistillInput{FindingID: 1, Name: "x", Severity: "low"}, nil)
	if offline.Title != "x" || offline.SuggestedMode != "new_entry" || offline.Kind != "methodology" {
		t.Fatalf("offline = %+v", offline)
	}
}
