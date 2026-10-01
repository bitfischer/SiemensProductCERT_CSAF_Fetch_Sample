package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKEVMatching(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"}]}`))
	}))
	defer srv.Close()

	cat, err := fetchKEV(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore()
	s.upsertCVE(&CVE{CVEID: "cve-2021-44228"})
	s.upsertCVE(&CVE{CVEID: "CVE-2020-0001"})
	s.upsertAdvisory(&Advisory{TrackingID: "A", CVEIDs: []string{"CVE-2021-44228", "CVE-2020-0001"}})
	s.setKEV(cat)

	hits := 0
	for _, c := range s.snapshotCVEs() {
		if c.KEV != nil {
			hits++
		}
	}
	if hits != 1 || s.snapshotStatus().KEVCount != 1 || s.snapshotAdvisories()[0].KEVCount != 1 {
		t.Fatalf("unexpected KEV matching, hits=%d", hits)
	}
}
