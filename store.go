// Copyright (c) 2026 Florian Fischer
//
// Use of this source code is governed by the MIT license found in the
// LICENSE file in the project root.

// store.go — in-memory storage for fetch results. This project has no
// database: one fetch run's results (and a rolling log trail) live in a
// mutex-guarded struct and are served straight to the frontend as JSON.
package main

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Reference is one external reference a CSAF document points at (NVD, GHSA,
// vendor bulletin, ...).
type Reference struct {
	Summary string `json:"summary,omitempty"`
	URL     string `json:"url"`
}

// CVE is the flattened per-vulnerability record produced from one CSAF
// advisory.
type CVE struct {
	CVEID         string      `json:"cve_id"`
	Title         string      `json:"title,omitempty"`
	Description   string      `json:"description,omitempty"`
	Severity      string      `json:"severity,omitempty"`
	CVSS3Score    float64     `json:"cvss3_score,omitempty"`
	CVSS3Vector   string      `json:"cvss3_vector,omitempty"`
	PublishedDate time.Time   `json:"published_date,omitempty"`
	ModifiedDate  time.Time   `json:"modified_date,omitempty"`
	Vendors       []string    `json:"vendors,omitempty"`
	Products      []string    `json:"products,omitempty"`
	References    []Reference `json:"references,omitempty"`
	AdvisoryURL   string      `json:"advisory_url,omitempty"`
}

// Advisory is the document-level record — one CSAF document, keyed on its
// tracking ID, describing 0..N CVEs.
type Advisory struct {
	TrackingID        string    `json:"tracking_id"`
	Title             string    `json:"title,omitempty"`
	Publisher         string    `json:"publisher,omitempty"`
	AggregateSeverity string    `json:"aggregate_severity,omitempty"`
	PublishedDate     time.Time `json:"published_date,omitempty"`
	ModifiedDate      time.Time `json:"modified_date,omitempty"`
	AdvisoryURL       string    `json:"advisory_url"`
	Vendors           []string  `json:"vendors,omitempty"`
	Products          []string  `json:"products,omitempty"`
	CVEIDs            []string  `json:"cve_ids"`
	Verification      string    `json:"verification"` // "verified" | "unverified"
}

// LogEntry is one line of the fetch trail.
type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // "info" | "warn" | "error"
	Message string    `json:"message"`
}

// Status is the live/last-run summary polled by the frontend.
type Status struct {
	Running         bool      `json:"running"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	FinishedAt      time.Time `json:"finished_at,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	Progress        string    `json:"progress,omitempty"`
	VerifiedCount   int       `json:"verified_count"`
	RejectedCount   int       `json:"rejected_count"`
	UnverifiedCount int       `json:"unverified_count"`
	AdvisoryCount   int       `json:"advisory_count"`
	CVECount        int       `json:"cve_count"`
}

const (
	logKeepRows    = 500 // rolling trail cap, mirrors feedLogKeepRows
	logMaxRejects  = 20  // per-run rejection lines before "further suppressed", mirrors feedLogMaxRejects
	progressEveryN = 20  // live "verifying N/total" cadence; Siemens is a few hundred advisories, not BSI's ~12k
)

// Store holds everything one Siemens ProductCERT fetch run produces, plus
// the conditional-GET cache (ETag/Last-Modified/last-fetched time) that
// makes the *next* run incremental instead of a full re-pull.
type Store struct {
	mu sync.RWMutex

	advisories map[string]*Advisory // keyed by TrackingID
	cves       map[string]*CVE      // keyed by CVEID
	log        []LogEntry
	rejectsThisRun int

	status Status

	// Conditional-GET / incremental-fetch cache from the previous successful
	// run — mirrors CSAFFeed.LastFetched/LastFetchURL/LastFetchETag/
	// LastFetchModified in the full app.
	lastFetched       *time.Time
	lastFetchURL      string
	lastFetchETag     string
	lastFetchModified string
}

func NewStore() *Store {
	return &Store{
		advisories: make(map[string]*Advisory),
		cves:       make(map[string]*CVE),
	}
}

// beginRun resets the log trail and per-run counters for a fresh fetch.
// Previously fetched advisories/CVEs are kept — a subsequent run is
// incremental and only touches entries the provider reports as updated.
func (s *Store) beginRun() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = nil
	s.rejectsThisRun = 0
	s.status = Status{Running: true, StartedAt: time.Now()}
}

func (s *Store) endRun(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Running = false
	s.status.FinishedAt = time.Now()
	s.status.Progress = ""
	if err != nil {
		s.status.LastError = err.Error()
	} else {
		s.status.LastError = ""
	}
	s.status.AdvisoryCount = len(s.advisories)
	s.status.CVECount = len(s.cves)
}

func (s *Store) setProgress(msg string) {
	s.mu.Lock()
	s.status.Progress = msg
	s.mu.Unlock()
}

// logEvent appends one trail entry and mirrors it to slog, writing into
// the in-memory ring.
func (s *Store) logEvent(level, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	switch level {
	case "error":
		slog.Error("fetch: " + msg)
	case "warn":
		slog.Warn("fetch: " + msg)
	default:
		slog.Info("fetch: " + msg)
	}
	s.mu.Lock()
	s.log = append(s.log, LogEntry{Time: time.Now(), Level: level, Message: msg})
	if len(s.log) > logKeepRows {
		s.log = s.log[len(s.log)-logKeepRows:]
	}
	s.mu.Unlock()
}

// logRejectEvent caps rejection lines at N per run, then emits one
// "further suppressed" line, so a poisoned feed can't flood the trail.
func (s *Store) logRejectEvent(url string, err error) {
	s.mu.Lock()
	s.rejectsThisRun++
	n := s.rejectsThisRun
	s.mu.Unlock()
	if n <= logMaxRejects {
		s.logEvent("error", "REJECTED %s — %v (document discarded)", url, err)
	} else if n == logMaxRejects+1 {
		s.logEvent("error", "further rejections suppressed in this trail — see counters in the summary")
	}
}

func (s *Store) incVerified() {
	s.mu.Lock()
	s.status.VerifiedCount++
	s.mu.Unlock()
}

func (s *Store) incRejected() {
	s.mu.Lock()
	s.status.RejectedCount++
	s.mu.Unlock()
}

func (s *Store) incUnverified() {
	s.mu.Lock()
	s.status.UnverifiedCount++
	s.mu.Unlock()
}

func (s *Store) upsertAdvisory(a *Advisory) {
	s.mu.Lock()
	s.advisories[a.TrackingID] = a
	s.mu.Unlock()
}

func (s *Store) upsertCVE(c *CVE) {
	s.mu.Lock()
	s.cves[c.CVEID] = c
	s.mu.Unlock()
}

// snapshotStatus returns a copy safe to marshal outside the lock.
func (s *Store) snapshotStatus() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.status
	st.AdvisoryCount = len(s.advisories)
	st.CVECount = len(s.cves)
	return st
}

func (s *Store) snapshotLog() []LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]LogEntry, len(s.log))
	copy(out, s.log)
	return out
}

func (s *Store) snapshotAdvisories() []*Advisory {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Advisory, 0, len(s.advisories))
	for _, a := range s.advisories {
		out = append(out, a)
	}
	return out
}

func (s *Store) snapshotCVEs() []*CVE {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*CVE, 0, len(s.cves))
	for _, c := range s.cves {
		out = append(out, c)
	}
	return out
}
