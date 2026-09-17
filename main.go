// Copyright (c) 2026 Florian Fischer
//
// Use of this source code is governed by the MIT license found in the
// LICENSE file in the project root.

// main.go — HTTP server for the standalone Siemens ProductCERT CSAF fetch
// extraction. Serves a tiny frontend plus a small JSON API to trigger a fetch
// and inspect its results, backed by the in-memory Store.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

// feedURL is the Siemens ProductCERT CSAF provider-metadata document.
const feedURL = "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json"

//go:embed web/index.html
var webFS embed.FS

var (
	store = NewStore()

	runMu   sync.Mutex
	running bool
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	mux := http.NewServeMux()

	index, err := fs.Sub(webFS, "web")
	if err != nil {
		slog.Error("embed fs.Sub failed", "error", err)
		os.Exit(1)
	}
	mux.Handle("/", http.FileServer(http.FS(index)))

	mux.HandleFunc("/api/fetch", handleFetch)
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/log", handleLog)
	mux.HandleFunc("/api/advisories", handleAdvisories)
	mux.HandleFunc("/api/cves", handleCVEs)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	slog.Info("siemens productcert csaf fetch listening", "port", port, "feed_url", feedURL)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}

// handleFetch triggers an immediate fetch. Refuses a second concurrent
// fetch (409) rather than doubling upstream load on Siemens.
func handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	runMu.Lock()
	if running {
		runMu.Unlock()
		http.Error(w, `{"error":"a fetch is already running"}`, http.StatusConflict)
		return
	}
	running = true
	runMu.Unlock()

	go func() {
		defer func() {
			runMu.Lock()
			running = false
			runMu.Unlock()
		}()
		runFetch()
	}()

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"started"}`))
}

// retryFetch retries fn up to maxAttempts times with exponential backoff.
func retryFetch(ctx context.Context, maxAttempts int, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt)) * 2 * time.Second
			slog.Warn("feed fetch failed, retrying", "attempt", attempt, "retry_in", delay, "error", lastErr)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

// runFetch performs one full (or incremental) fetch of the Siemens
// ProductCERT feed: prune the log, run with a bounded timeout and retries,
// record the outcome.
func runFetch() {
	store.beginRun()
	defer recoverFeedFetch(store)
	store.logEvent("info", "fetch started (Siemens ProductCERT, %s)", feedURL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	err := retryFetch(ctx, 3, func() error {
		return fetchProviderMetadata(ctx, store, feedURL)
	})

	now := time.Now()
	store.mu.Lock()
	store.lastFetched = &now
	store.mu.Unlock()

	if err != nil {
		store.logEvent("error", "fetch failed: %v", err)
	} else {
		st := store.snapshotStatus()
		store.logEvent("info", "fetch complete: %d verified, %d rejected, %d unverified — %d advisories, %d CVEs total",
			st.VerifiedCount, st.RejectedCount, st.UnverifiedCount, len(store.snapshotAdvisories()), len(store.snapshotCVEs()))
	}
	store.endRun(err)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, store.snapshotStatus())
}

func handleLog(w http.ResponseWriter, r *http.Request) {
	entries := store.snapshotLog()
	// newest first, easier to read in the frontend
	sort.Slice(entries, func(i, j int) bool { return entries[i].Time.After(entries[j].Time) })
	writeJSON(w, entries)
}

func handleAdvisories(w http.ResponseWriter, r *http.Request) {
	advisories := store.snapshotAdvisories()
	sort.Slice(advisories, func(i, j int) bool {
		return advisories[i].PublishedDate.After(advisories[j].PublishedDate)
	})
	writeJSON(w, advisories)
}

func handleCVEs(w http.ResponseWriter, r *http.Request) {
	cves := store.snapshotCVEs()
	sort.Slice(cves, func(i, j int) bool { return cves[i].CVEID > cves[j].CVEID })
	writeJSON(w, cves)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("json encode failed", "error", err)
	}
}
