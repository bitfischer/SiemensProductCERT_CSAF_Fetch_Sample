// Copyright (c) 2026 Florian Fischer
//
// Use of this source code is governed by the MIT license found in the
// LICENSE file in the project root.

// parse.go — pure CSAF advisory parser. No DB or HTTP — bytes → parsed
// Advisory + CVEs.
package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// cveIDRe matches the canonical CVE identifier format: CVE-YYYY-NNNNN
// (case-insensitive).
var cveIDRe = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

// ── CSAF JSON document shapes ────────────────────────────────────────────────

type csafCVSSv3 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Branches []csafBranch `json:"branches"`
}

type csafReference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

type csafAdvisory struct {
	Document struct {
		Title    string `json:"title"`
		Tracking struct {
			ID                 string `json:"id"`
			InitialReleaseDate string `json:"initial_release_date"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
		AggregateSeverity struct {
			Text string `json:"text"`
		} `json:"aggregate_severity"`
		Publisher struct {
			Name string `json:"name"`
		} `json:"publisher"`
		References []csafReference `json:"references"`
	} `json:"document"`
	ProductTree struct {
		Branches         []csafBranch `json:"branches"`
		FullProductNames []struct {
			ProductID string `json:"product_id"`
			Name      string `json:"name"`
		} `json:"full_product_names"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE   string `json:"cve"`
		Title string `json:"title"`
		IDs   []struct {
			SystemName string `json:"system_name"`
			Text       string `json:"text"`
		} `json:"ids"`
		Notes []struct {
			Category string `json:"category"`
			Text     string `json:"text"`
		} `json:"notes"`
		Scores []struct {
			CVSSv3  *csafCVSSv3 `json:"cvss_v3,omitempty"`
			CVSSv31 *csafCVSSv3 `json:"cvss_v31,omitempty"`
		} `json:"scores"`
	} `json:"vulnerabilities"`
}

type vendorProductPair struct{ Vendor, Product string }

// parsedCSAFAdvisory is the in-memory representation produced by
// parseCSAFAdvisory.
type parsedCSAFAdvisory struct {
	CVEs         []CVE
	CatalogPairs []vendorProductPair
	Advisory     Advisory
}

func parseFlexTime(s string) time.Time {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",        // no timezone
		"2006-01-02T15:04:05.999999", // no timezone, fractional
		"2006-01-02",                 // date only
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// aggregateSeverityToEnglish maps localised aggregate_severity.text values to
// the canonical English severity labels. Returns "" when unrecognised.
func aggregateSeverityToEnglish(text string) string {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "critical", "kritisch":
		return "CRITICAL"
	case "high", "hoch":
		return "HIGH"
	case "medium", "mittel", "moderate":
		return "MEDIUM"
	case "low", "niedrig", "gering":
		return "LOW"
	default:
		return ""
	}
}

func scoreToCVSSSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

// collectVendorProductPairs walks the CSAF product tree and returns all
// (vendor, product_name) pairs found in vendor → product_name sub-branches.
func collectVendorProductPairs(branches []csafBranch) []vendorProductPair {
	var pairs []vendorProductPair
	for _, b := range branches {
		if b.Category == "vendor" && b.Name != "" {
			for _, p := range collectBranches(b.Branches, "product_name") {
				pairs = append(pairs, vendorProductPair{Vendor: b.Name, Product: p})
			}
		} else {
			pairs = append(pairs, collectVendorProductPairs(b.Branches)...)
		}
	}
	return pairs
}

// collectBranches recursively collects distinct branch names matching category.
func collectBranches(branches []csafBranch, category string) []string {
	seen := map[string]struct{}{}
	var walk func([]csafBranch)
	walk = func(bs []csafBranch) {
		for _, b := range bs {
			if b.Category == category && b.Name != "" {
				seen[b.Name] = struct{}{}
			}
			walk(b.Branches)
		}
	}
	walk(branches)
	result := make([]string, 0, len(seen))
	for k := range seen {
		result = append(result, k)
	}
	return result
}

// parseCSAFAdvisory converts a CSAF 2.0 advisory JSON document into the
// in-memory shape this app stores. Each vulnerability entry with a
// resolvable CVE ID becomes one entry in CVEs[]. Vulnerabilities whose CVE ID
// can't be resolved to the canonical CVE-YYYY-NNNNN form are silently
// skipped.
func parseCSAFAdvisory(data []byte, advisoryURL string) (*parsedCSAFAdvisory, error) {
	var advisory csafAdvisory
	if err := json.Unmarshal(data, &advisory); err != nil {
		return nil, err
	}

	publishedDate := parseFlexTime(advisory.Document.Tracking.InitialReleaseDate)
	modifiedDate := parseFlexTime(advisory.Document.Tracking.CurrentReleaseDate)
	aggregateSev := aggregateSeverityToEnglish(advisory.Document.AggregateSeverity.Text)

	var references []Reference
	for _, r := range advisory.Document.References {
		if r.Category == "external" && r.URL != "" {
			references = append(references, Reference{Summary: r.Summary, URL: r.URL})
		}
	}

	vendors := collectBranches(advisory.ProductTree.Branches, "vendor")
	products := collectBranches(advisory.ProductTree.Branches, "product_name")
	for _, fp := range advisory.ProductTree.FullProductNames {
		if fp.Name != "" {
			products = append(products, fp.Name)
		}
	}
	catalogPairs := collectVendorProductPairs(advisory.ProductTree.Branches)

	cves := make([]CVE, 0, len(advisory.Vulnerabilities))
	for _, vuln := range advisory.Vulnerabilities {
		cveID := strings.ToUpper(vuln.CVE)
		if !cveIDRe.MatchString(cveID) {
			for _, id := range vuln.IDs {
				if t := strings.ToUpper(id.Text); cveIDRe.MatchString(t) {
					cveID = t
					break
				}
			}
		}
		if !cveIDRe.MatchString(cveID) {
			continue
		}

		description := ""
		for _, note := range vuln.Notes {
			if note.Category == "description" || note.Category == "summary" {
				description = note.Text
				break
			}
		}

		var cvssScore float64
		var cvssVector, severity string
		for _, s := range vuln.Scores {
			v3 := s.CVSSv31
			if v3 == nil {
				v3 = s.CVSSv3
			}
			if v3 != nil {
				cvssScore = v3.BaseScore
				cvssVector = v3.VectorString
				severity = strings.ToUpper(v3.BaseSeverity)
				break
			}
		}
		if severity == "" && aggregateSev != "" {
			severity = aggregateSev
		}
		if severity == "" {
			severity = scoreToCVSSSeverity(cvssScore)
		}

		title := vuln.Title
		if title == "" {
			title = advisory.Document.Title
		}

		cves = append(cves, CVE{
			CVEID:         cveID,
			Title:         title,
			Description:   description,
			Severity:      severity,
			CVSS3Score:    cvssScore,
			CVSS3Vector:   cvssVector,
			PublishedDate: publishedDate,
			ModifiedDate:  modifiedDate,
			Vendors:       vendors,
			Products:      products,
			References:    references,
			AdvisoryURL:   advisoryURL,
		})
	}

	advisoryDoc := Advisory{
		TrackingID:        advisory.Document.Tracking.ID,
		Title:             advisory.Document.Title,
		Publisher:         advisory.Document.Publisher.Name,
		AggregateSeverity: aggregateSev,
		PublishedDate:     publishedDate,
		ModifiedDate:      modifiedDate,
		AdvisoryURL:       advisoryURL,
		Vendors:           vendors,
		Products:          products,
	}
	for _, c := range cves {
		advisoryDoc.CVEIDs = append(advisoryDoc.CVEIDs, c.CVEID)
	}

	return &parsedCSAFAdvisory{
		CVEs:         cves,
		CatalogPairs: catalogPairs,
		Advisory:     advisoryDoc,
	}, nil
}
