// Package kb pulls public vulnerability intelligence into kb_entries.
package kb

import (
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Draft is one record a source parser emits before merge.
type Draft struct {
	NKey              string
	ExternalID        string
	Aliases           []string
	SourceKey         string
	Kind              string
	VulnClass         string
	Severity          string
	CVSS              float64
	CWE               string
	ActivelyExploited bool
	Products          []string
	CPE               []string
	AffectedVersions  string
	Tags              []string
	Title             string
	Summary           string
	DetectionGuide    string
	PocSnippet        string
	Remediation       string
	References        []db.KBReference
	PublishedAt       *time.Time
}

// Entry converts a draft into the row the store merges. Products stay raw;
// UpsertAndMergeKBEntry normalizes them.
func (d Draft) Entry() db.KBEntry {
	keys := []string{}
	if k := strings.TrimSpace(d.SourceKey); k != "" {
		keys = []string{k}
	}
	return db.KBEntry{
		NKey:              d.NKey,
		ExternalID:        d.ExternalID,
		Aliases:           d.Aliases,
		SourceKeys:        keys,
		Origin:            "synced",
		Kind:              d.Kind,
		VulnClass:         d.VulnClass,
		Severity:          strings.ToLower(strings.TrimSpace(d.Severity)),
		CVSS:              d.CVSS,
		CWE:               d.CWE,
		ActivelyExploited: d.ActivelyExploited,
		Products:          d.Products,
		CPE:               d.CPE,
		AffectedVersions:  d.AffectedVersions,
		Tags:              d.Tags,
		Title:             d.Title,
		Summary:           d.Summary,
		DetectionGuide:    d.DetectionGuide,
		PocSnippet:        d.PocSnippet,
		Remediation:       d.Remediation,
		References:        d.References,
		PublishedAt:       d.PublishedAt,
		Enabled:           true,
	}
}
