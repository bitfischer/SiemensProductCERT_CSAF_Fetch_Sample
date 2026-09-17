// Copyright (c) 2026 Florian Fischer
//
// Use of this source code is governed by the MIT license found in the
// LICENSE file in the project root.

// rolie.go — CSAF/ROLIE protocol implementation, trimmed to the single path
// Siemens ProductCERT uses: provider-metadata.json → ROLIE distribution
// feeds → advisory documents.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// ── provider-metadata / ROLIE JSON shapes ────────────────────────────────────

type csafProviderMeta struct {
	LastUpdated   string     `json:"last_updated"`
	Distributions []csafDist `json:"distributions"`
	Publisher     struct {
		Name string `json:"name"`
	} `json:"publisher"`
	PGPKeys []struct {
		Fingerprint string `json:"fingerprint"`
		URL         string `json:"url"`
	} `json:"public_openpgp_keys"`
}

type csafDist struct {
	Rolie *csafRolie `json:"rolie,omitempty"`
}

type csafRolie struct {
	Feeds []csafFeedEntry `json:"feeds"`
}

type csafFeedEntry struct {
	TLP struct{ Label string } `json:"tlp"`
	URL string                 `json:"url"`
}

type csafRolieFeed struct {
	Feed struct {
		Link []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"link"`
		Entry []struct {
			ID      string `json:"id"`
			Title   string `json:"title"`
			Updated string `json:"updated"`
			Content struct {
				Src string `json:"src"`
			} `json:"content"`
			Link []struct {
				Rel  string `json:"rel"`
				Href string `json:"href"`
			} `json:"link"`
		} `json:"entry"`
	} `json:"feed"`
}

// rolieAdvisoryWorkers bounds how many advisories are downloaded + verified
// concurrently. This is the second half of the rate-limiting fix: past a
// handful of workers, more concurrency just provokes provider rate-limiting
// (→ more docs stored unverified) without going faster, since the
// signature-preferred verification in verify.go already halved the per-
// advisory request count.
const rolieAdvisoryWorkers = 8

// fetchProviderMetadata fetches the CSAF provider-metadata document at
// feedURL, walks each ROLIE distribution feed, and stores the discovered
// advisories/CVEs on store.
func fetchProviderMetadata(ctx context.Context, store *Store, feedURL string) error {
	client := newSafeHTTPClient(60 * time.Second)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("fetch provider metadata: HTTP %d", resp.StatusCode)
	}
	warnContentType(resp, feedURL, jsonContentTypes)

	body, err := limitedReadAll(resp, maxProviderMetadataBytes)
	if err != nil {
		return err
	}

	var meta csafProviderMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		return fmt.Errorf("parse provider metadata: %w", err)
	}

	lastFetched := incrementalCutoff(store)
	store.logEvent("info", "provider metadata loaded (publisher %q, %d PGP key(s) advertised)", meta.Publisher.Name, len(meta.PGPKeys))
	verifier := &feedVerifier{store: store, keyring: loadProviderPGPKeys(ctx, client, &meta)}
	store.logEvent("info", "%d OpenPGP key(s) loaded for signature verification", len(verifier.keyring))

	for _, dist := range meta.Distributions {
		if dist.Rolie == nil {
			continue
		}
		for _, entry := range dist.Rolie.Feeds {
			if err := fetchRolieFeed(ctx, client, entry.URL, store, lastFetched, verifier); err != nil {
				slog.Warn("rolie feed fetch failed", "url", entry.URL, "error", err)
				store.logEvent("warn", "ROLIE distribution feed fetch failed: %s — %v", entry.URL, err)
			}
		}
	}
	return nil
}

// incrementalCutoff decides whether to do a full re-pull: nil forces one
// (first run, or a run started with an empty store); otherwise only
// entries updated since the previous successful run are downloaded.
func incrementalCutoff(store *Store) *time.Time {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if len(store.advisories) == 0 {
		return nil
	}
	return store.lastFetched
}

// roliePage is the result of fetching one ROLIE feed page.
type roliePage struct {
	Entries      []rolieEntryRef
	NextURL      string
	NotModified  bool
	ETag         string
	LastModified string
}

// fetchRolieFeed collects all advisory URLs across paginated ROLIE feed
// pages, then downloads and verifies each advisory using a bounded worker
// pool.
//
// The first page of the walk is fetched with conditional headers
// (If-None-Match / If-Modified-Since) when store's cached LastFetchURL still
// matches AND lastFetched is set — a 304 means the whole feed is unchanged,
// so the walk stops immediately without downloading a single advisory.
func fetchRolieFeed(ctx context.Context, client *http.Client, url string, store *Store, lastFetched *time.Time, verifier *feedVerifier) error {
	var refs []rolieEntryRef
	nextURL := url
	firstPage := true
	for nextURL != "" {
		var condETag, condLastModified string
		store.mu.RLock()
		if firstPage && lastFetched != nil && store.lastFetchURL == nextURL {
			condETag = store.lastFetchETag
			condLastModified = store.lastFetchModified
		}
		store.mu.RUnlock()

		page, err := fetchRoliePage(ctx, client, nextURL, lastFetched, condETag, condLastModified)
		if err != nil {
			return err
		}
		if page.NotModified {
			slog.Info("rolie feed unchanged since last fetch, skipping download", "url", nextURL)
			store.logEvent("info", "feed unchanged upstream (HTTP 304) — nothing to download")
			return nil
		}
		if firstPage {
			store.mu.Lock()
			store.lastFetchURL = nextURL
			store.lastFetchETag = page.ETag
			store.lastFetchModified = page.LastModified
			store.mu.Unlock()
			firstPage = false
		}
		refs = append(refs, page.Entries...)
		nextURL = page.NextURL
	}
	total := len(refs)
	slog.Info("rolie feed collected", "url", url, "advisories", total)
	store.logEvent("info", "ROLIE feed walked: %d advisory document(s) to download and verify", total)

	var (
		wg        sync.WaitGroup
		sem       = make(chan struct{}, rolieAdvisoryWorkers)
		processed = struct {
			sync.Mutex
			n int
		}{}
	)
	for _, ref := range refs {
		ref := ref
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer recoverWorker("rolie_advisory", ref.URL)
			if err := fetchAndParseAdvisory(ctx, client, ref, store, verifier); err != nil {
				slog.Warn("advisory fetch skipped", "url", ref.URL, "error", err)
			}
			processed.Lock()
			processed.n++
			n := processed.n
			processed.Unlock()
			// Progress feedback so a run of a few hundred advisories doesn't sit
			// on a static "fetching…" for its whole duration.
			if n%progressEveryN == 0 {
				store.setProgress(fmt.Sprintf("verifying advisories: %d/%d…", n, total))
			}
		}()
	}
	wg.Wait()
	return nil
}

// fetchRoliePage fetches one page of a ROLIE JSON feed. When condETag/
// condLastModified are non-empty they're sent as If-None-Match/
// If-Modified-Since; a 304 response short-circuits with NotModified=true.
func fetchRoliePage(ctx context.Context, client *http.Client, url string, lastFetched *time.Time, condETag, condLastModified string) (roliePage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return roliePage{}, err
	}
	if condETag != "" {
		req.Header.Set("If-None-Match", condETag)
	}
	if condLastModified != "" {
		req.Header.Set("If-Modified-Since", condLastModified)
	}
	resp, err := client.Do(req)
	if err != nil {
		return roliePage{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return roliePage{NotModified: true}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return roliePage{}, fmt.Errorf("fetch ROLIE feed: HTTP %d", resp.StatusCode)
	}

	var rolie csafRolieFeed
	if err := json.NewDecoder(limitedBody(resp, maxRoliePageBytes)).Decode(&rolie); err != nil {
		return roliePage{}, err
	}

	result := roliePage{
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}
	for _, l := range rolie.Feed.Link {
		if l.Rel == "next" {
			result.NextURL = l.Href
			break
		}
	}

	for _, entry := range rolie.Feed.Entry {
		if lastFetched != nil && !lastFetched.IsZero() && entry.Updated != "" {
			if t := parseFlexTime(entry.Updated); !t.IsZero() && !t.After(*lastFetched) {
				continue
			}
		}
		var ref rolieEntryRef
		for _, link := range entry.Link {
			switch link.Rel {
			case "self":
				if ref.URL == "" {
					ref.URL = link.Href
				}
			case "hash":
				ref.HashURLs = append(ref.HashURLs, link.Href)
			case "signature":
				ref.SigURL = link.Href
			}
		}
		if ref.URL == "" {
			ref.URL = entry.Content.Src
		}
		if ref.URL != "" {
			result.Entries = append(result.Entries, ref)
		}
	}
	return result, nil
}

// fetchAndParseAdvisory downloads a single CSAF advisory JSON document,
// verifies it against the integrity data its ROLIE entry advertised, parses
// it, and upserts the advisory + its CVEs into store.
func fetchAndParseAdvisory(ctx context.Context, client *http.Client, ref rolieEntryRef, store *Store, verifier *feedVerifier) error {
	url := ref.URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("fetch advisory: HTTP %d", resp.StatusCode)
	}

	body, err := limitedReadAll(resp, maxAdvisoryBytes)
	if err != nil {
		return err
	}

	// Reject+alert policy: a document whose advertised hash/signature does not
	// verify is discarded here, before any parsing or store write.
	verified, err := verifyAdvisory(ctx, client, ref, body, verifier)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	parsed, err := parseCSAFAdvisory(body, url)
	if err != nil {
		return err
	}

	for i := range parsed.CVEs {
		store.upsertCVE(&parsed.CVEs[i])
	}

	adv := parsed.Advisory
	if adv.TrackingID == "" {
		adv.TrackingID = adv.AdvisoryURL // fall back to the URL as identity
	}
	if adv.TrackingID == "" {
		return nil // no usable identity — not worth storing
	}
	adv.Verification = "unverified"
	if verified {
		adv.Verification = "verified"
	}
	store.upsertAdvisory(&adv)

	return nil
}
