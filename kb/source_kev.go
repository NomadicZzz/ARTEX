package kb

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Autumn-27/artex/db"
)

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type kevCatalog struct {
	CatalogVersion  string `json:"catalogVersion"`
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		ShortDescription           string `json:"shortDescription"`
		RequiredAction             string `json:"requiredAction"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		Notes                      string `json:"notes"`
	} `json:"vulnerabilities"`
}

// ParseKEV decodes a CISA KEV catalog. Exposed for tests.
func ParseKEV(body []byte, sourceKey string) (drafts []Draft, version string, err error) {
	var cat kevCatalog
	if err = json.Unmarshal(body, &cat); err != nil {
		return nil, "", err
	}
	if sourceKey == "" {
		sourceKey = "cisa_kev"
	}
	for _, v := range cat.Vulnerabilities {
		cve := upperCVE(v.CVEID)
		if cve == "" {
			continue
		}
		products := []string{}
		if p := strings.TrimSpace(v.Product); p != "" {
			products = append(products, p)
		}
		if vendor := strings.TrimSpace(v.VendorProject); vendor != "" && !strings.EqualFold(vendor, v.Product) {
			products = append(products, vendor+" "+v.Product)
		}
		var refs []db.KBReference
		for _, note := range strings.Split(v.Notes, ";") {
			note = strings.TrimSpace(note)
			if strings.HasPrefix(note, "http://") || strings.HasPrefix(note, "https://") {
				refs = append(refs, db.KBReference{URL: note, Title: "KEV note"})
			}
		}
		title := strings.TrimSpace(v.VulnerabilityName)
		if title == "" {
			title = cve
		}
		guide := GuideKEV
		if v.KnownRansomwareCampaignUse == "Known" {
			guide += GuideKEVRansomware
		}
		drafts = append(drafts, Draft{
			ExternalID:        cve,
			SourceKey:         sourceKey,
			Kind:              "cve",
			Severity:          "high",
			ActivelyExploited: true,
			Products:          products,
			Title:             title,
			Summary:           v.ShortDescription,
			DetectionGuide:    guide,
			Remediation:       v.RequiredAction,
			References:        refs,
			Tags:              []string{"kev"},
			PublishedAt:       parseTimeFlexible(v.DateAdded),
		})
	}
	return drafts, cat.CatalogVersion, nil
}

func syncKEV(ctx context.Context, c *Client, src db.KBSource, emit func(Draft) error) (string, error) {
	body, _, err := c.GetBytes(ctx, kevURL, nil, 32<<20)
	if err != nil {
		return src.Cursor, err
	}
	drafts, version, err := ParseKEV(body, src.Key)
	if err != nil {
		return src.Cursor, err
	}
	if version != "" && version == src.Cursor {
		return version, nil
	}
	for _, d := range drafts {
		if err := emit(d); err != nil {
			return version, err
		}
	}
	return version, nil
}
