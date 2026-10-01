// Copyright (c) 2026 Florian Fischer
//
// Use of this source code is governed by the MIT license found in the
// LICENSE file in the project root.

// kev.go — fetches the CISA Known Exploited Vulnerabilities (KEV) catalog so
// CVEs from the Siemens feed can be flagged when they are actively exploited.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// kevURL is the CISA KEV catalog in JSON form.
const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// maxKEVBytes caps the KEV download — the real catalog is ~1–2 MiB.
const maxKEVBytes = 16 << 20

// KEVInfo is the CISA KEV catalog entry attached to a matching CVE.
type KEVInfo struct {
	VendorProject     string `json:"vendor_project,omitempty"`
	Product           string `json:"product,omitempty"`
	VulnerabilityName string `json:"vulnerability_name,omitempty"`
	DateAdded         string `json:"date_added,omitempty"`
	DueDate           string `json:"due_date,omitempty"`
	RequiredAction    string `json:"required_action,omitempty"`
	RansomwareUse     string `json:"ransomware_use,omitempty"`
}

type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID             string `json:"cveID"`
		VendorProject     string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		RequiredAction    string `json:"requiredAction"`
		DueDate           string `json:"dueDate"`
		RansomwareUse     string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// fetchKEV downloads and parses the CISA KEV catalog, keyed by upper-case CVE ID.
func fetchKEV(ctx context.Context, client *http.Client, url string) (map[string]*KEVInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KEV catalog: unexpected status %s", resp.Status)
	}
	warnContentType(resp, url, jsonContentTypes)
	body, err := limitedReadAll(resp, maxKEVBytes)
	if err != nil {
		return nil, err
	}
	var cat kevCatalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, fmt.Errorf("KEV catalog: %w", err)
	}
	out := make(map[string]*KEVInfo, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if id == "" {
			continue
		}
		out[id] = &KEVInfo{
			VendorProject:     v.VendorProject,
			Product:           v.Product,
			VulnerabilityName: v.VulnerabilityName,
			DateAdded:         v.DateAdded,
			DueDate:           v.DueDate,
			RequiredAction:    v.RequiredAction,
			RansomwareUse:     v.RansomwareUse,
		}
	}
	return out, nil
}

// refreshKEV fetches the catalog (with retries) and stores it. Failure is
// non-fatal for the overall run: Siemens data stays usable without KEV flags.
func refreshKEV(ctx context.Context, store *Store) {
	var cat map[string]*KEVInfo
	err := retryFetch(ctx, 3, func() (err error) {
		cat, err = fetchKEV(ctx, newSafeHTTPClient(60*time.Second), kevURL)
		return err
	})
	if err != nil {
		store.logEvent("warn", "CISA KEV fetch failed, KEV flags unavailable: %v", err)
		return
	}
	store.setKEV(cat)
	matched := 0
	for _, c := range store.snapshotCVEs() {
		if c.KEV != nil {
			matched++
		}
	}
	store.logEvent("info", "CISA KEV catalog loaded: %d entries, %d matching Siemens CVEs", len(cat), matched)
}
