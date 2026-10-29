package server

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/kb"
)

const maxReportUploadBytes = 20 << 20

// kbParseReportFile extracts an uploaded report and returns candidate entries.
// It does not write. The client confirms the selection through POST /api/kb/import.
func (s *Server) kbParseReportFile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxReportUploadBytes); err != nil {
		writeErr(w, 400, "上传内容超过 20MB 或不是 multipart")
		return
	}
	if r.MultipartForm == nil {
		writeErr(w, 400, "请上传报告文件")
		return
	}
	files := append([]*multipart.FileHeader{}, r.MultipartForm.File["file"]...)
	files = append(files, r.MultipartForm.File["files"]...)
	if len(files) == 0 {
		writeErr(w, 400, "请上传报告文件")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	var (
		names   []string
		formats []string
		entries []db.KBEntry
		chunks  int
		used    bool
	)
	budget := maxReportUploadBytes
	for _, fh := range files {
		data, err := readUpload(fh, budget)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		budget -= len(data)
		names = append(names, fh.Filename)
		md, format, err := kb.ExtractReportText(fh.Filename, data)
		if err != nil {
			writeErr(w, 400, fh.Filename+": "+err.Error())
			return
		}
		formats = append(formats, format)
		if format == "json" {
			if parsed, ok := kb.ParseReportJSONEntries(md); ok {
				entries = append(entries, parsed...)
				continue
			}
		}
		parts := kb.SplitReportIntoChunks(md, 6000)
		chunks += len(parts)
		got, llm := kb.DistillReportChunks(ctx, parts, formUseLLM(r), s.completeDistill)
		if llm {
			used = true
		}
		entries = append(entries, got...)
	}
	entries = kb.DedupeReportEntries(entries)
	if len(entries) > 50 {
		entries = entries[:50]
	}
	if entries == nil {
		entries = []db.KBEntry{}
	}
	writeJSON(w, 200, map[string]any{
		"files_processed": names,
		"format":          reportFormat(formats),
		"chunk_count":     chunks,
		"used_llm":        used,
		"entries":         entries,
	})
}

func readUpload(fh *multipart.FileHeader, budget int) ([]byte, error) {
	if budget <= 0 || (fh.Size > 0 && fh.Size > int64(budget)) {
		return nil, fmt.Errorf("上传内容超过 20MB")
	}
	f, err := fh.Open()
	if err != nil {
		return nil, fmt.Errorf("无法读取 %s", fh.Filename)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(budget)+1))
	if err != nil {
		return nil, fmt.Errorf("无法读取 %s", fh.Filename)
	}
	if len(data) > budget {
		return nil, fmt.Errorf("上传内容超过 20MB")
	}
	return data, nil
}

func formUseLLM(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.FormValue("use_llm"))) {
	case "", "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

func reportFormat(formats []string) string {
	if len(formats) == 0 {
		return ""
	}
	first := formats[0]
	for _, f := range formats[1:] {
		if f != first {
			return "mixed"
		}
	}
	return first
}
