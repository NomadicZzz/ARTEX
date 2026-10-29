package kb

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestExtractDOCX(t *testing.T) {
	const doc = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:pPr><w:pStyle w:val="Heading1"/></w:pPr>
      <w:r><w:t>Spring Cloud Gateway RCE</w:t></w:r>
    </w:p>
    <w:p>
      <w:r><w:t>GET /actuator/gateway/routes HTTP/1.1</w:t></w:r>
      <w:r><w:br/></w:r>
      <w:r><w:t>Host: oa.example</w:t></w:r>
    </w:p>
    <w:tbl>
      <w:tr>
        <w:tc><w:p><w:r><w:t>漏洞名称</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>风险等级</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:t>网关 RCE</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>严重</w:t></w:r></w:p></w:tc>
      </w:tr>
    </w:tbl>
  </w:body>
</w:document>`
	text, format, err := ExtractReportText("report.docx", zipDocx(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if format != "docx" {
		t.Fatalf("format %s", format)
	}
	if !strings.Contains(text, "# Spring Cloud Gateway RCE") {
		t.Fatalf("missing heading:\n%s", text)
	}
	if !strings.Contains(text, "GET /actuator/gateway/routes HTTP/1.1\nHost: oa.example") {
		t.Fatalf("HTTP newline was flattened:\n%s", text)
	}
	if !strings.Contains(text, "| 漏洞名称 | 风险等级 |") || !strings.Contains(text, "| 网关 RCE | 严重 |") {
		t.Fatalf("table missing:\n%s", text)
	}
}

func TestExtractHTML(t *testing.T) {
	const page = `<html><head><title>ignored</title><script>SECRET_NOISE</script></head>
<body>
<nav>导航噪音</nav>
<h1>登录绕过</h1>
<table>
  <tr><th>漏洞</th><th>等级</th></tr>
  <tr><td>认证绕过</td><td>高危</td></tr>
</table>
<pre><code>POST /login HTTP/1.1
Host: oa.example</code></pre>
<script>alert(1)</script>
</body></html>`
	text, format, err := ExtractReportText("awvs.html", []byte(page))
	if err != nil {
		t.Fatal(err)
	}
	if format != "html" {
		t.Fatalf("format %s", format)
	}
	if !strings.Contains(text, "# 登录绕过") {
		t.Fatalf("heading:\n%s", text)
	}
	if !strings.Contains(text, "| 漏洞 | 等级 |") || !strings.Contains(text, "| 认证绕过 | 高危 |") {
		t.Fatalf("table:\n%s", text)
	}
	if !strings.Contains(text, "```http\nPOST /login HTTP/1.1\nHost: oa.example\n```") {
		t.Fatalf("packet:\n%s", text)
	}
	if strings.Count(text, "```http") != 1 {
		t.Fatalf("double fence:\n%s", text)
	}
	if strings.Contains(text, "SECRET_NOISE") || strings.Contains(text, "alert(1)") || strings.Contains(text, "导航噪音") {
		t.Fatalf("noise kept:\n%s", text)
	}
}

func TestExtractPDFPureGo(t *testing.T) {
	text, err := extractPDFPureGo(flatePDF(t, "BT /F1 12 Tf (Spring Cloud Gateway RCE) Tj ET"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Spring Cloud Gateway RCE") {
		t.Fatalf("pdf text %q", text)
	}
}

func TestExtractTextCharset(t *testing.T) {
	raw, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte("漏洞名称 Spring"))
	if err != nil {
		t.Fatal(err)
	}
	text, format, err := ExtractReportText("notes.txt", raw)
	if err != nil {
		t.Fatal(err)
	}
	if format != "txt" {
		t.Fatalf("format %s", format)
	}
	if !strings.Contains(text, "漏洞名称") {
		t.Fatalf("gbk text %q", text)
	}
}

func zipDocx(t *testing.T, documentXML string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(documentXML)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func flatePDF(t *testing.T, content string) []byte {
	t.Helper()
	var payload bytes.Buffer
	zw := zlib.NewWriter(&payload)
	if _, err := zw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	comp := payload.Bytes()
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	fmt.Fprintf(&b, "1 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", len(comp))
	b.Write(comp)
	b.WriteString("\nendstream\nendobj\n%%EOF\n")
	return b.Bytes()
}
