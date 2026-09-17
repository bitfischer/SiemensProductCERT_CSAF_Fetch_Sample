// Copyright (c) 2026 Florian Fischer
//
// Use of this source code is governed by the MIT license found in the
// LICENSE file in the project root.

// guard.go — ingestion guard layer ("feed firewall"). Every byte pulled
// from the Siemens ProductCERT feed passes through the size caps here
// before it is parsed.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"runtime/debug"
)

// Download size caps for the paths this project actually uses
// (provider-metadata + ROLIE page + advisory + hash sidecar + signature +
// PGP key).
const (
	maxProviderMetadataBytes = 2 << 20   // 2 MiB   — real provider-metadata.json is 5–50 KiB
	maxRoliePageBytes        = 128 << 20 // 128 MiB — headroom for a large single-page ROLIE feed
	maxAdvisoryBytes         = 32 << 20  // 32 MiB  — largest vendor CSAF docs are single-digit MB
	maxHashFileBytes         = 4 << 10   // 4 KiB   — one hex digest + filename
	maxSignatureBytes        = 64 << 10  // 64 KiB  — armored detached OpenPGP signature is ~1 KiB
	maxPGPKeyBytes           = 1 << 20   // 1 MiB   — armored public key with subkeys is 5–100 KiB
)

// limitedReadAll reads the response body, rejecting it when it exceeds
// maxBytes. A Content-Length above the cap is rejected before reading;
// chunked/lying responses are caught by reading at most maxBytes+1.
func limitedReadAll(resp *http.Response, maxBytes int64) ([]byte, error) {
	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("feedguard: response too large (Content-Length %d > cap %d bytes)", resp.ContentLength, maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("feedguard: response exceeds cap of %d bytes", maxBytes)
	}
	return body, nil
}

// limitedBody wraps a response body for streaming decoders so they cannot be
// fed more than maxBytes.
func limitedBody(resp *http.Response, maxBytes int64) io.ReadCloser {
	return http.MaxBytesReader(nil, resp.Body, maxBytes)
}

var jsonContentTypes = []string{"application/json", "text/plain", "application/octet-stream"}

// warnContentType logs a warning when the response Content-Type is not in the
// accepted set. Warn-only by design: real CSAF providers serve JSON as
// text/plain or octet-stream, so rejecting would break a legitimate feed —
// the size caps and strict parser are the actual defense.
func warnContentType(resp *http.Response, url string, accepted []string) {
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		return
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		slog.Warn("feedguard: unparseable Content-Type", "url", url, "content_type", ct)
		return
	}
	for _, a := range accepted {
		if mediaType == a {
			return
		}
	}
	slog.Warn("feedguard: unexpected Content-Type", "url", url, "content_type", mediaType)
}

// recoverFeedFetch is deferred in the top-level fetch goroutine. On panic it
// logs the stack and records the error on the store — a poisoned document
// degrades the run instead of crashing the server.
func recoverFeedFetch(store *Store) {
	if r := recover(); r != nil {
		slog.Error("feed fetch panicked", "panic", r, "stack", string(debug.Stack()))
		store.endRun(fmt.Errorf("panic: %v", r))
	}
}

// recoverWorker is deferred in per-advisory worker goroutines; a panic on one
// malformed document logs and skips that document so the batch continues.
func recoverWorker(worker, item string) {
	if r := recover(); r != nil {
		slog.Error("feed worker panicked",
			"worker", worker, "item", item, "panic", r, "stack", string(debug.Stack()))
	}
}
