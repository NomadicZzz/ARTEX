package db

import (
	"encoding/json"
)

// DistillTrafficSample is one captured exchange kept for distillation.
// Heads always come from the finding snapshot. Hashes let the server attach a
// short body when the evidence file is still on disk.
type DistillTrafficSample struct {
	Method   string
	URL      string
	Status   int
	Role     string
	ReqHead  string
	RespHead string
	ReqHash  string
	RespHash string
	ReqLen   int64
	RespLen  int64
}

// FindingDistillSource is the material gathered for one finding.
type FindingDistillSource struct {
	Finding  *DBFinding
	Products []string
	Traffic  []DistillTrafficSample
	Linked   []KBEntry
	// Distilled is true when a linked row was produced or enriched by distillation.
	Distilled bool
}

// GetFindingDistillSource loads the finding, normalized asset products, up to
// three request-bearing traffic samples, and the linked knowledge rows.
func (d *DB) GetFindingDistillSource(findingID int64) (*FindingDistillSource, error) {
	f, err := d.GetFinding(findingID)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}
	out := &FindingDistillSource{Finding: f}
	products, err := d.assetProductNames(f.AssetIDs)
	if err != nil {
		return nil, err
	}
	out.Products = NormalizeProducts(products)
	traffic, err := d.distillTraffic(findingID)
	if err != nil {
		return nil, err
	}
	out.Traffic = traffic
	if len(f.KBEntryIDs) > 0 {
		rows, err := d.ListKBEntriesByIDs(f.KBEntryIDs)
		if err != nil {
			return nil, err
		}
		out.Linked = rows
		for _, row := range rows {
			if row.Origin == "finding_distilled" || hasString(row.SourceKeys, "finding_distilled") {
				out.Distilled = true
			}
		}
	}
	return out, nil
}

func (d *DB) assetProductNames(ids []int64) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := d.Query(`SELECT COALESCE(array_to_json(technologies)::text,'[]'), COALESCE(service_name,''), COALESCE(app_name,'')
		FROM assets WHERE id = ANY($1::bigint[])`, int64Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var techJSON, service, app string
		if err := rows.Scan(&techJSON, &service, &app); err != nil {
			return nil, err
		}
		var techs []string
		_ = json.Unmarshal([]byte(techJSON), &techs)
		out = append(out, techs...)
		if service != "" {
			out = append(out, service)
		}
		if app != "" {
			out = append(out, app)
		}
	}
	return out, rows.Err()
}

func (d *DB) distillTraffic(findingID int64) ([]DistillTrafficSample, error) {
	rows, err := d.Query(`SELECT COALESCE(s.method,''), COALESCE(s.url,''), COALESCE(s.status,0), COALESCE(b.role,''),
		COALESCE(s.req_head,''), COALESCE(s.resp_head,''), COALESCE(s.req_hash,''), COALESCE(s.resp_hash,''),
		COALESCE(s.req_len,0), COALESCE(s.resp_len,0)
		FROM finding_traffic_bindings b
		JOIN traffic_evidence_snapshots s ON s.id = b.snapshot_id
		WHERE b.finding_id=$1 AND btrim(s.req_head) <> ''
		ORDER BY CASE b.role WHEN 'proof' THEN 0 WHEN 'verification' THEN 1 ELSE 2 END, b.created_at DESC
		LIMIT 3`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DistillTrafficSample
	for rows.Next() {
		var s DistillTrafficSample
		if err := rows.Scan(&s.Method, &s.URL, &s.Status, &s.Role, &s.ReqHead, &s.RespHead, &s.ReqHash, &s.RespHash, &s.ReqLen, &s.RespLen); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func hasString(items []string, want string) bool {
	for _, s := range items {
		if s == want {
			return true
		}
	}
	return false
}
