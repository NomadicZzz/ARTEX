package kb

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/saintfish/chardet"
	"golang.org/x/net/html"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// ExtractReportText turns an uploaded report into structured Markdown.
// detectedFormat is pdf, docx, html, markdown, txt, or json.
// Routing uses the extension and the magic bytes (%PDF- or a PK zip header).
func ExtractReportText(filename string, data []byte) (string, string, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return "", "", fmt.Errorf("文件为空")
	}
	ext := strings.ToLower(filepath.Ext(filename))
	if bytes.HasPrefix(data, []byte("%PDF-")) || ext == ".pdf" {
		text, err := extractPDF(data)
		return normalizeNewlines(text), "pdf", err
	}
	if isZIPMagic(data) && (ext == ".docx" || zipHas(data, "word/document.xml")) {
		text, err := extractDOCX(data)
		return text, "docx", err
	}
	switch ext {
	case ".docx":
		text, err := extractDOCX(data)
		return text, "docx", err
	case ".html", ".htm":
		text := normalizeNewlines(decodeUploadText(data))
		md, err := extractHTML([]byte(text))
		return md, "html", err
	case ".md", ".markdown":
		return normalizeNewlines(decodeUploadText(data)), "markdown", nil
	case ".txt":
		return normalizeNewlines(decodeUploadText(data)), "txt", nil
	case ".json":
		return normalizeNewlines(decodeUploadText(data)), "json", nil
	default:
		if ext == "" {
			ext = "未知"
		}
		return "", "", fmt.Errorf("不支持的文件类型 %s", ext)
	}
}

func isZIPMagic(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4
}

func zipHas(data []byte, name string) bool {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	name = strings.ToLower(name)
	for _, f := range zr.File {
		if strings.ToLower(f.Name) == name {
			return true
		}
	}
	return false
}

func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

func isChineseCharset(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "gb-18030", "gb18030", "gbk", "gb2312", "hz-gb-2312":
		return true
	default:
		return false
	}
}

// decodeUploadText keeps valid UTF-8. GBK / GB18030 HTML, Markdown, and text
// are converted before the structure parser runs.
func decodeUploadText(data []byte) string {
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		data = data[3:]
	}
	if utf8.Valid(data) {
		return string(data)
	}
	det, err := chardet.NewTextDetector().DetectBest(data)
	if err == nil && det != nil && isChineseCharset(det.Charset) {
		if s, ok := decodeGB18030(data); ok {
			return s
		}
	}
	if s, ok := decodeGB18030(data); ok {
		return s
	}
	return strings.ToValidUTF8(string(data), "")
}

func decodeGB18030(data []byte) (string, bool) {
	out, err := simplifiedchinese.GB18030.NewDecoder().Bytes(data)
	if err != nil || !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}

func extractDOCX(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("无法读取 docx：%w", err)
	}
	var doc *zip.File
	for _, f := range zr.File {
		if strings.EqualFold(f.Name, "word/document.xml") {
			doc = f
			break
		}
	}
	if doc == nil {
		return "", fmt.Errorf("docx 中没有 word/document.xml")
	}
	rc, err := doc.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	return docxToMarkdown(rc)
}

type docxTable struct {
	rows     [][]string
	row      []string
	cell     strings.Builder
	cellOpen bool
}

func docxToMarkdown(r io.Reader) (string, error) {
	dec := xml.NewDecoder(r)
	var out strings.Builder
	var tables []docxTable
	var pOpen bool
	var inText bool
	var pStyle string
	var pText strings.Builder

	flushP := func() {
		text := pText.String()
		style := pStyle
		pText.Reset()
		pStyle = ""
		pOpen = false
		if len(tables) > 0 && tables[len(tables)-1].cellOpen {
			cell := &tables[len(tables)-1].cell
			if cell.Len() > 0 && strings.TrimSpace(text) != "" {
				cell.WriteByte('\n')
			}
			cell.WriteString(text)
			return
		}
		if len(tables) > 0 {
			return
		}
		writeDOCXParagraph(&out, style, text)
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("解析 document.xml 失败：%w", err)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			switch el.Name.Local {
			case "Fallback":
				if err := skipXML(dec); err != nil {
					return "", err
				}
			case "tbl":
				tables = append(tables, docxTable{})
			case "tr":
				if n := len(tables); n > 0 {
					tables[n-1].row = nil
				}
			case "tc":
				if n := len(tables); n > 0 {
					tables[n-1].cell.Reset()
					tables[n-1].cellOpen = true
				}
			case "p":
				pOpen = true
				pStyle = ""
				pText.Reset()
			case "pStyle":
				if pOpen {
					pStyle = xmlAttr(el, "val")
				}
			case "br", "cr":
				pText.WriteByte('\n')
			case "tab":
				pText.WriteByte('\t')
			case "t":
				inText = true
			}
		case xml.EndElement:
			switch el.Name.Local {
			case "t":
				inText = false
			case "p":
				if pOpen {
					flushP()
				}
			case "tc":
				if n := len(tables); n > 0 && tables[n-1].cellOpen {
					tables[n-1].row = append(tables[n-1].row, tables[n-1].cell.String())
					tables[n-1].cell.Reset()
					tables[n-1].cellOpen = false
				}
			case "tr":
				if n := len(tables); n > 0 {
					tables[n-1].rows = append(tables[n-1].rows, tables[n-1].row)
					tables[n-1].row = nil
				}
			case "tbl":
				if n := len(tables); n > 0 {
					rendered := markdownTable(tables[n-1].rows)
					tables = tables[:n-1]
					if len(tables) > 0 && tables[len(tables)-1].cellOpen {
						tables[len(tables)-1].cell.WriteString(rendered)
					} else if strings.TrimSpace(rendered) != "" {
						out.WriteString(rendered)
						if !strings.HasSuffix(rendered, "\n") {
							out.WriteByte('\n')
						}
						out.WriteByte('\n')
					}
				}
			}
		case xml.CharData:
			if pOpen && inText {
				pText.Write(el)
			}
		}
	}
	if pOpen {
		flushP()
	}
	return strings.TrimSpace(out.String()), nil
}

func skipXML(dec *xml.Decoder) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		}
	}
	return nil
}

func xmlAttr(el xml.StartElement, local string) string {
	for _, a := range el.Attr {
		if a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

func writeDOCXParagraph(out *strings.Builder, style, text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	if prefix := headingMarks(style); prefix != "" {
		line := strings.Join(strings.Fields(text), " ")
		out.WriteString(prefix)
		out.WriteString(line)
		out.WriteString("\n\n")
		return
	}
	out.WriteString(strings.TrimRight(text, " \t"))
	out.WriteString("\n\n")
}

func headingMarks(style string) string {
	s := strings.ToLower(strings.TrimSpace(style))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "　", "")
	switch s {
	case "heading1", "1", "标题1", "title":
		return "# "
	case "heading2", "2", "标题2":
		return "## "
	case "heading3", "3", "标题3":
		return "### "
	case "heading4", "4", "标题4":
		return "#### "
	default:
		return ""
	}
}

func markdownTable(rows [][]string) string {
	var clean [][]string
	cols := 0
	for _, row := range rows {
		empty := true
		for _, c := range row {
			if strings.TrimSpace(c) != "" {
				empty = false
				break
			}
		}
		if empty {
			continue
		}
		if len(row) > cols {
			cols = len(row)
		}
		clean = append(clean, row)
	}
	if len(clean) == 0 || cols == 0 {
		return ""
	}
	var b strings.Builder
	writeRow := func(row []string) {
		b.WriteString("|")
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(row) {
				cell = cellText(row[i])
			}
			b.WriteString(" ")
			b.WriteString(cell)
			b.WriteString(" |")
		}
		b.WriteByte('\n')
	}
	writeRow(clean[0])
	b.WriteString("|")
	for i := 0; i < cols; i++ {
		b.WriteString(" --- |")
	}
	b.WriteByte('\n')
	for _, row := range clean[1:] {
		writeRow(row)
	}
	return b.String()
}

func cellText(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "<br>")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func extractHTML(data []byte) (string, error) {
	root, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("无法解析 HTML：%w", err)
	}
	return strings.TrimSpace(renderHTML(root)), nil
}

func renderHTML(n *html.Node) string {
	if n == nil {
		return ""
	}
	if n.Type == html.TextNode {
		return n.Data
	}
	if n.Type != html.ElementNode {
		return renderHTMLChildren(n)
	}
	tag := strings.ToLower(n.Data)
	switch tag {
	case "script", "style", "svg", "noscript", "head", "nav":
		return ""
	case "h1", "h2", "h3", "h4":
		level := int(tag[1] - '0')
		text := strings.TrimSpace(inlineText(n))
		if text == "" {
			return ""
		}
		return strings.Repeat("#", level) + " " + text + "\n\n"
	case "pre", "textarea":
		text := strings.Trim(rawText(n), "\n")
		if strings.TrimSpace(text) == "" {
			return ""
		}
		return "```http\n" + text + "\n```\n\n"
	case "code":
		text := rawText(n)
		if strings.Contains(text, "\n") || httpStartLine.MatchString(text) {
			text = strings.Trim(text, "\n")
			return "```http\n" + text + "\n```\n\n"
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return ""
		}
		return "`" + text + "`"
	case "table":
		rendered := markdownTable(htmlTableRows(n))
		if rendered == "" {
			return ""
		}
		return rendered + "\n"
	case "br":
		return "\n"
	case "p", "li":
		inner := strings.TrimSpace(renderHTMLChildren(n))
		if inner == "" {
			return ""
		}
		return inner + "\n\n"
	default:
		return renderHTMLChildren(n)
	}
}

func renderHTMLChildren(n *html.Node) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		b.WriteString(renderHTML(c))
	}
	return b.String()
}

func inlineText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			return
		}
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			if tag == "script" || tag == "style" || tag == "svg" || tag == "noscript" {
				return
			}
			if tag == "br" {
				b.WriteByte(' ')
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

func rawText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			return
		}
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			if tag == "script" || tag == "style" || tag == "svg" || tag == "noscript" {
				return
			}
			if tag == "br" {
				b.WriteByte('\n')
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

func htmlTableRows(n *html.Node) [][]string {
	var rows [][]string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "tr") {
			var cells []string
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type != html.ElementNode {
					continue
				}
				tag := strings.ToLower(c.Data)
				if tag == "td" || tag == "th" {
					cells = append(cells, inlineText(c))
				}
			}
			if len(cells) > 0 {
				rows = append(rows, cells)
			}
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return rows
}

func extractPDF(data []byte) (string, error) {
	if path, err := exec.LookPath("pdftotext"); err == nil {
		if text, err := runPDFToText(path, data); err == nil && strings.TrimSpace(text) != "" {
			return text, nil
		}
	}
	return extractPDFPureGo(data)
}

func runPDFToText(bin string, data []byte) (string, error) {
	f, err := os.CreateTemp("", "artex-report-*.pdf")
	if err != nil {
		return "", err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	cmd := exec.Command(bin, "-layout", "-nopgbrk", name, "-")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// extractPDFPureGo reads FlateDecode streams and the BT…ET text operators.
// It is the fallback when pdftotext is not installed. It is not a full PDF parser.
func extractPDFPureGo(data []byte) (string, error) {
	streams := pdfStreams(data)
	cmap := map[string]string{}
	for _, raw := range streams {
		if bytes.Contains(raw, []byte("beginbfchar")) || bytes.Contains(raw, []byte("beginbfrange")) {
			parseToUnicode(raw, cmap)
		}
	}
	var texts []string
	for _, raw := range streams {
		if !bytes.Contains(raw, []byte("BT")) {
			continue
		}
		text := strings.TrimSpace(parsePDFTextObjects(raw, cmap))
		if text != "" {
			texts = append(texts, text)
		}
	}
	out := strings.TrimSpace(strings.Join(texts, "\n"))
	if out == "" {
		return "", fmt.Errorf("未能从 PDF 提取文本")
	}
	return out, nil
}

func pdfStreams(data []byte) [][]byte {
	var out [][]byte
	budget := 32 << 20
	i := 0
	for i < len(data) && budget > 0 {
		rel := bytes.Index(data[i:], []byte("stream"))
		if rel < 0 {
			break
		}
		abs := i + rel
		if abs > 0 && isPDFWordByte(data[abs-1]) {
			i = abs + 6
			continue
		}
		dict := precedingDict(data, abs)
		if dict == "" {
			i = abs + 6
			continue
		}
		start := abs + len("stream")
		if start < len(data) && data[start] == '\r' {
			start++
		}
		if start < len(data) && data[start] == '\n' {
			start++
		}
		var payload []byte
		if n, ok := pdfStreamLength(dict); ok && n >= 0 && start+n <= len(data) {
			payload = data[start : start+n]
			i = start + n
		} else {
			end := bytes.Index(data[start:], []byte("endstream"))
			if end < 0 {
				break
			}
			payload = bytes.TrimRight(data[start:start+end], "\r\n")
			i = start + end + len("endstream")
		}
		decoded, ok := decodePDFStream(dict, payload)
		if !ok || len(decoded) == 0 || len(decoded) > budget {
			continue
		}
		budget -= len(decoded)
		out = append(out, decoded)
	}
	return out
}

func isPDFWordByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '*' || b == '\'' || b == '"'
}

func precedingDict(data []byte, streamAt int) string {
	window := streamAt - 1200
	if window < 0 {
		window = 0
	}
	prev := bytes.TrimRight(data[window:streamAt], " \t\r\n")
	if !bytes.HasSuffix(prev, []byte(">>")) {
		return ""
	}
	rel := bytes.LastIndex(prev, []byte("<<"))
	if rel < 0 {
		return ""
	}
	return string(prev[rel:])
}

var (
	pdfLengthDirect   = regexp.MustCompile(`/Length\s+(\d+)\b`)
	pdfLengthIndirect = regexp.MustCompile(`/Length\s+\d+\s+\d+\s+R\b`)
)

func pdfStreamLength(dict string) (int, bool) {
	if pdfLengthIndirect.MatchString(dict) && !pdfLengthDirect.MatchString(strings.Replace(dict, pdfLengthIndirect.FindString(dict), "", 1)) {
		// An indirect /Length has no inline integer. A dict can also carry both;
		// prefer a direct integer that is not the object number of an indirect ref.
	}
	if pdfLengthIndirect.MatchString(dict) {
		direct := pdfLengthDirect.FindAllStringSubmatchIndex(dict, -1)
		for _, loc := range direct {
			after := dict[loc[1]:]
			if regexp.MustCompile(`^\s+\d+\s+R\b`).MatchString(after) {
				continue
			}
			n, err := strconv.Atoi(dict[loc[2]:loc[3]])
			if err == nil {
				return n, true
			}
		}
		return 0, false
	}
	m := pdfLengthDirect.FindStringSubmatch(dict)
	if len(m) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

func decodePDFStream(dict string, payload []byte) ([]byte, bool) {
	if strings.Contains(dict, "/FlateDecode") {
		return inflatePDF(payload)
	}
	if strings.Contains(dict, "/Filter") {
		return nil, false
	}
	return payload, true
}

func inflatePDF(b []byte) ([]byte, bool) {
	if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
		out, err := io.ReadAll(io.LimitReader(zr, 8<<20))
		zr.Close()
		if err == nil && len(out) > 0 {
			return out, true
		}
	}
	fr := flate.NewReader(bytes.NewReader(b))
	out, err := io.ReadAll(io.LimitReader(fr, 8<<20))
	fr.Close()
	if err == nil && len(out) > 0 {
		return out, true
	}
	return nil, false
}

func parseToUnicode(data []byte, dst map[string]string) {
	s := string(data)
	for _, block := range regexp.MustCompile(`(?s)beginbfchar(.*?)endbfchar`).FindAllStringSubmatch(s, -1) {
		for _, p := range regexp.MustCompile(`<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>`).FindAllStringSubmatch(block[1], -1) {
			src := decodeHexBytes(p[1])
			text := utf16beToString(decodeHexBytes(p[2]))
			if len(src) > 0 && text != "" {
				dst[string(src)] = text
			}
		}
	}
	for _, block := range regexp.MustCompile(`(?s)beginbfrange(.*?)endbfrange`).FindAllStringSubmatch(s, -1) {
		for _, p := range regexp.MustCompile(`<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>`).FindAllStringSubmatch(block[1], -1) {
			start := decodeHexBytes(p[1])
			end := decodeHexBytes(p[2])
			dest := decodeHexBytes(p[3])
			addCMapRange(dst, start, end, dest)
		}
	}
}

func addCMapRange(dst map[string]string, start, end, dest []byte) {
	if len(start) == 0 || len(start) != len(end) || len(start) > 4 || len(dest) == 0 {
		return
	}
	from := bytesToInt(start)
	to := bytesToInt(end)
	if to < from || to-from > 1024 {
		return
	}
	code := append([]byte(nil), dest...)
	for n := from; n <= to; n++ {
		src := intToBytes(n, len(start))
		dst[string(src)] = utf16beToString(code)
		incUTF16(code)
	}
}

func bytesToInt(b []byte) int {
	n := 0
	for _, c := range b {
		n = n<<8 | int(c)
	}
	return n
}

func intToBytes(n, size int) []byte {
	out := make([]byte, size)
	for i := size - 1; i >= 0; i-- {
		out[i] = byte(n)
		n >>= 8
	}
	return out
}

func incUTF16(b []byte) {
	if len(b) < 2 {
		return
	}
	i := len(b) - 2
	u := int(b[i])<<8 | int(b[i+1])
	u++
	b[i] = byte(u >> 8)
	b[i+1] = byte(u)
}

func decodeHexBytes(s string) []byte {
	s = strings.TrimSpace(s)
	if len(s)%2 == 1 {
		s += "0"
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return raw
}

func utf16beToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) == 1 {
		return string(rune(b[0]))
	}
	if b[0] == 0xFE && b[1] == 0xFF {
		b = b[2:]
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return string(utf16.Decode(u))
}

type pdfOp struct {
	kind string
	num  float64
	str  string
}

func parsePDFTextObjects(data []byte, cmap map[string]string) string {
	var b strings.Builder
	var stack []pdfOp
	inBT := false
	i := 0
	for i < len(data) {
		i = skipPDFSpace(data, i)
		if i >= len(data) {
			break
		}
		switch data[i] {
		case '(':
			s, ni := readPDFLiteral(data, i)
			stack = append(stack, pdfOp{kind: "str", str: decodePDFBytes([]byte(s), cmap)})
			i = ni
		case '<':
			if i+1 < len(data) && data[i+1] == '<' {
				i = skipPDFDict(data, i)
				continue
			}
			s, ni, ok := readPDFHex(data, i, cmap)
			if ok {
				stack = append(stack, pdfOp{kind: "str", str: s})
			}
			i = ni
		case '[':
			s, ni := readPDFArray(data, i, cmap)
			stack = append(stack, pdfOp{kind: "str", str: s})
			i = ni
		case '/':
			name, ni := readPDFName(data, i)
			stack = append(stack, pdfOp{kind: "name", str: name})
			i = ni
		case '%':
			for i < len(data) && data[i] != '\n' && data[i] != '\r' {
				i++
			}
		default:
			if isPDFNumStart(data, i) {
				num, ni, ok := readPDFNumber(data, i)
				if ok {
					stack = append(stack, pdfOp{kind: "num", num: num})
					i = ni
					continue
				}
			}
			kw, ni := readPDFKeyword(data, i)
			if kw == "" {
				i++
				continue
			}
			i = ni
			if kw == "BT" {
				inBT = true
				stack = nil
				continue
			}
			if !inBT {
				continue
			}
			if kw == "ET" {
				inBT = false
				stack = nil
				if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
					b.WriteByte('\n')
				}
				continue
			}
			applyPDFOp(&b, kw, &stack)
		}
	}
	return b.String()
}

func skipPDFSpace(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\r', '\n', '\f', 0:
			i++
		default:
			return i
		}
	}
	return i
}

func skipPDFDict(data []byte, i int) int {
	depth := 0
	for i < len(data) {
		if data[i] == '<' && i+1 < len(data) && data[i+1] == '<' {
			depth++
			i += 2
			continue
		}
		if data[i] == '>' && i+1 < len(data) && data[i+1] == '>' {
			depth--
			i += 2
			if depth == 0 {
				return i
			}
			continue
		}
		i++
	}
	return i
}

func readPDFLiteral(data []byte, i int) (string, int) {
	var b strings.Builder
	depth := 1
	i++
	for i < len(data) && depth > 0 {
		c := data[i]
		if c == '\\' && i+1 < len(data) {
			n := data[i+1]
			switch n {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case '(', ')', '\\':
				b.WriteByte(n)
			case '\n':
			case '\r':
				if i+2 < len(data) && data[i+2] == '\n' {
					i++
				}
			default:
				if n >= '0' && n <= '7' {
					oct := []byte{n}
					k := i + 2
					for len(oct) < 3 && k < len(data) && data[k] >= '0' && data[k] <= '7' {
						oct = append(oct, data[k])
						k++
					}
					v := 0
					for _, d := range oct {
						v = v*8 + int(d-'0')
					}
					b.WriteByte(byte(v))
					i = k
					continue
				}
				b.WriteByte(n)
			}
			i += 2
			continue
		}
		if c == '(' {
			depth++
			b.WriteByte(c)
			i++
			continue
		}
		if c == ')' {
			depth--
			if depth == 0 {
				return b.String(), i + 1
			}
			b.WriteByte(c)
			i++
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), i
}

func readPDFHex(data []byte, i int, cmap map[string]string) (string, int, bool) {
	j := i + 1
	var hexb strings.Builder
	for j < len(data) && data[j] != '>' {
		if data[j] != ' ' && data[j] != '\n' && data[j] != '\r' && data[j] != '\t' {
			hexb.WriteByte(data[j])
		}
		j++
	}
	if j >= len(data) {
		return "", i + 1, false
	}
	raw := decodeHexBytes(hexb.String())
	return decodePDFBytes(raw, cmap), j + 1, true
}

func readPDFArray(data []byte, i int, cmap map[string]string) (string, int) {
	var b strings.Builder
	i++
	for i < len(data) {
		i = skipPDFSpace(data, i)
		if i >= len(data) {
			break
		}
		switch data[i] {
		case ']':
			return b.String(), i + 1
		case '(':
			s, ni := readPDFLiteral(data, i)
			b.WriteString(decodePDFBytes([]byte(s), cmap))
			i = ni
		case '<':
			s, ni, ok := readPDFHex(data, i, cmap)
			if ok {
				b.WriteString(s)
			}
			i = ni
		default:
			if isPDFNumStart(data, i) {
				num, ni, ok := readPDFNumber(data, i)
				if ok {
					if num <= -80 {
						b.WriteByte(' ')
					}
					i = ni
					continue
				}
			}
			i++
		}
	}
	return b.String(), i
}

func readPDFName(data []byte, i int) (string, int) {
	i++
	start := i
	for i < len(data) {
		c := data[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '/' || c == '(' || c == ')' || c == '<' || c == '>' || c == '[' || c == ']' || c == '{' || c == '}' || c == '%' {
			break
		}
		i++
	}
	return string(data[start:i]), i
}

func isPDFNumStart(data []byte, i int) bool {
	c := data[i]
	if c >= '0' && c <= '9' || c == '.' {
		return true
	}
	if (c == '+' || c == '-') && i+1 < len(data) {
		n := data[i+1]
		return (n >= '0' && n <= '9') || n == '.'
	}
	return false
}

func readPDFNumber(data []byte, i int) (float64, int, bool) {
	start := i
	if data[i] == '+' || data[i] == '-' {
		i++
	}
	saw := false
	for i < len(data) && data[i] >= '0' && data[i] <= '9' {
		saw = true
		i++
	}
	if i < len(data) && data[i] == '.' {
		i++
		for i < len(data) && data[i] >= '0' && data[i] <= '9' {
			saw = true
			i++
		}
	}
	if !saw {
		return 0, start, false
	}
	n, err := strconv.ParseFloat(string(data[start:i]), 64)
	if err != nil {
		return 0, start, false
	}
	return n, i, true
}

func readPDFKeyword(data []byte, i int) (string, int) {
	start := i
	for i < len(data) && isPDFWordByte(data[i]) {
		i++
	}
	if i == start {
		return "", i
	}
	return string(data[start:i]), i
}

func decodePDFBytes(raw []byte, cmap map[string]string) string {
	if len(raw) == 0 {
		return ""
	}
	if len(raw) >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
		return utf16beToString(raw)
	}
	if len(cmap) > 0 {
		var b strings.Builder
		for i := 0; i < len(raw); {
			matched := false
			for _, n := range []int{4, 2, 1} {
				if i+n <= len(raw) {
					if s, ok := cmap[string(raw[i:i+n])]; ok {
						b.WriteString(s)
						i += n
						matched = true
						break
					}
				}
			}
			if matched {
				continue
			}
			b.WriteByte(raw[i])
			i++
		}
		return b.String()
	}
	if utf8.Valid(raw) {
		return string(raw)
	}
	var b strings.Builder
	for _, c := range raw {
		b.WriteRune(rune(c))
	}
	return b.String()
}

func applyPDFOp(b *strings.Builder, kw string, stack *[]pdfOp) {
	pop := func(n int) []pdfOp {
		if n > len(*stack) {
			n = len(*stack)
		}
		if n == 0 {
			return nil
		}
		out := append([]pdfOp(nil), (*stack)[len(*stack)-n:]...)
		*stack = (*stack)[:len(*stack)-n]
		return out
	}
	emit := func(ops []pdfOp) {
		for _, op := range ops {
			if op.kind == "str" {
				b.WriteString(op.str)
			}
		}
	}
	switch kw {
	case "Tj", "TJ":
		emit(pop(1))
	case "'":
		ops := pop(1)
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		emit(ops)
	case "\"":
		ops := pop(3)
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		emit(ops)
	case "T*":
		b.WriteByte('\n')
	case "Td", "TD":
		ops := pop(2)
		y := 0.0
		if len(ops) == 2 && ops[1].kind == "num" {
			y = ops[1].num
		}
		if y != 0 {
			b.WriteByte('\n')
		}
	case "Tf", "Tc", "Tw", "Tz", "TL", "Tr", "Ts":
		pop(2)
	default:
	}
}
