// Copyright (c) 2026 Florian Fischer
//
// Use of this source code is governed by the MIT license found in the
// LICENSE file in the project root.

// verify.go — cryptographic verification of CSAF advisory documents (the
// exact logic behind the rate-limiting fix this project exists to
// demonstrate).
//
// CSAF providers publish a SHA-256/512 hash file and an OpenPGP detached
// signature next to every advisory (ROLIE rel="hash" / rel="signature"
// links) plus their public keys in provider-metadata.json. The decisive
// distinction is between *tampering* (an artifact is present but does not
// match — always reject) and *unavailability* (the artifact can't be
// fetched, e.g. provider rate-limiting — accept unverified rather than
// discard a legitimate advisory):
//
//   - signature advertised AND provider keys held → verify the OpenPGP
//     detached signature. It proves integrity and authenticity, so the
//     (redundant) hash is NOT downloaded — this is what halves the request
//     count per advisory and is the fix for Siemens ProductCERT rate-limiting
//     a manual/scheduled fetch that checked both hash and signature.
//   - if the signature can't be fetched, fall back to the hash sidecar.
//   - a wrong signature or wrong hash → reject (tampering detected).
//   - artifacts advertised but none reachable → accept, counted unverified.
//   - nothing advertised → accept; neither verified nor rejected.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
)

// rolieEntryRef is one advisory reference discovered on a ROLIE page,
// including its integrity links (CSAF 2.0 §7.1.19 / §7.1.20).
type rolieEntryRef struct {
	URL      string
	HashURLs []string // rel="hash": sidecar files ending in .sha256 / .sha512
	SigURL   string   // rel="signature": OpenPGP detached .asc
}

// feedVerifier carries the provider keyring and verification bookkeeping for
// one fetch run.
type feedVerifier struct {
	keyring openpgp.EntityList // nil = provider publishes no keys
	store   *Store

	warnedNoKeys  bool
	warnedNoFetch bool
}

type verifyOutcome int

const (
	verifyPass        verifyOutcome = iota // cryptographically verified
	verifyTampered                         // artifact present but wrong — reject
	verifyUnavailable                      // artifact could not be fetched — transient
)

// warnNoKeysOnce logs at most one warning per fetch when advisories advertise
// signatures but no provider key could be loaded (verification degrades to
// hash-only).
func (v *feedVerifier) warnNoKeysOnce(url string) {
	if v.warnedNoKeys {
		return
	}
	v.warnedNoKeys = true
	v.store.logEvent("warn", "advisories publish signatures but no provider OpenPGP keys are available — verification degraded to hash-only (example: %s)", url)
}

// warnNoFetchOnce logs at most one warning per fetch when integrity sidecars
// advertised by the feed can't be reached (provider rate-limiting, etc).
func (v *feedVerifier) warnNoFetchOnce() {
	if v.warnedNoFetch {
		return
	}
	v.warnedNoFetch = true
	v.store.logEvent("warn", "some advisories' hash/signature files were unavailable (provider rate-limiting or transient errors) — stored unverified; served content is still checked against any artifact that IS reachable")
}

// fetchCapped GETs url with the shared safe client and returns at most
// maxBytes of body.
func fetchCapped(ctx context.Context, client *http.Client, url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return limitedReadAll(resp, maxBytes)
}

// loadProviderPGPKeys fetches each public_openpgp_keys entry from the provider
// metadata, parses the armored key, and keeps it only when its primary-key
// fingerprint matches the advertised fingerprint. Individual key failures are
// warn-and-skip so one bad key doesn't disable verification for a provider
// that publishes several. Returns nil when no usable key was found.
func loadProviderPGPKeys(ctx context.Context, client *http.Client, meta *csafProviderMeta) openpgp.EntityList {
	var keyring openpgp.EntityList
	for _, k := range meta.PGPKeys {
		if k.URL == "" {
			continue
		}
		data, err := fetchCapped(ctx, client, k.URL, maxPGPKeyBytes)
		if err != nil {
			slog.Warn("provider OpenPGP key fetch failed — skipping key", "url", k.URL, "error", err)
			continue
		}
		entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
		if err != nil {
			slog.Warn("provider OpenPGP key unparseable — skipping key", "url", k.URL, "error", err)
			continue
		}
		want := strings.ToLower(strings.ReplaceAll(k.Fingerprint, " ", ""))
		for _, e := range entities {
			got := hex.EncodeToString(e.PrimaryKey.Fingerprint)
			if want != "" && got != want {
				slog.Warn("provider OpenPGP key fingerprint mismatch — skipping key",
					"url", k.URL, "advertised", want, "actual", got)
				continue
			}
			if want == "" {
				slog.Warn("provider metadata omits key fingerprint — accepting key as served", "url", k.URL)
			}
			keyring = append(keyring, e)
		}
	}
	return keyring
}

// deriveProviderMetadataURL maps a direct ROLIE feed URL to the host's
// well-known provider-metadata location. Unused for Siemens (whose feed URL
// already points at provider-metadata.json) but kept for parity with the
// source this was extracted from; harmless dead weight otherwise.
func deriveProviderMetadataURL(feedURL string) string {
	parsed, err := url.Parse(feedURL)
	if err != nil {
		return ""
	}
	const marker = "/.well-known/csaf/"
	idx := strings.Index(parsed.Path, marker)
	if idx < 0 {
		return ""
	}
	parsed.Path = parsed.Path[:idx+len(marker)] + "provider-metadata.json"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

// hashAlgoForURL picks the digest algorithm for a hash sidecar file. Unknown
// suffixes fall back to a hex-length heuristic on the file content.
func hashAlgoForURL(hashURL, content string) (algo string, digest func([]byte) string) {
	sha256Fn := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	sha512Fn := func(b []byte) string { s := sha512.Sum512(b); return hex.EncodeToString(s[:]) }
	switch {
	case strings.HasSuffix(hashURL, ".sha512"):
		return "sha512", sha512Fn
	case strings.HasSuffix(hashURL, ".sha256"):
		return "sha256", sha256Fn
	case len(content) == 128:
		return "sha512", sha512Fn
	case len(content) == 64:
		return "sha256", sha256Fn
	default:
		return "", nil
	}
}

// verifyIntegrity is the pure verification core: given a keyring and the
// integrity links a ROLIE entry advertised, it decides whether body is
// verified, tampered, or unverifiable — no logging or side effects.
func verifyIntegrity(ctx context.Context, client *http.Client, keyring openpgp.EntityList, ref rolieEntryRef, body []byte) (outcome verifyOutcome, expired bool, err error) {
	if ref.SigURL != "" && len(keyring) > 0 {
		if o, exp, e := checkSignature(ctx, client, keyring, ref, body); o != verifyUnavailable {
			return o, exp, e
		}
	}
	if len(ref.HashURLs) > 0 {
		o, e := checkHash(ctx, client, ref, body)
		return o, false, e
	}
	return verifyUnavailable, false, nil
}

// verifyAdvisory applies the live-fetch reject+alert policy on one downloaded
// document, recording the outcome on the verifier/store. It returns
// verified=true only when the document passed a hash/signature check, and a
// non-nil error only when the document must be discarded (tampering).
func verifyAdvisory(ctx context.Context, client *http.Client, ref rolieEntryRef, body []byte, v *feedVerifier) (verified bool, err error) {
	if len(ref.HashURLs) == 0 && ref.SigURL == "" {
		return false, nil // nothing advertised: stored, but unverified
	}
	outcome, expired, verr := verifyIntegrity(ctx, client, v.keyring, ref, body)
	switch outcome {
	case verifyPass:
		if expired {
			v.store.logEvent("warn", "signature on %s made with a since-expired provider key (cryptographically valid, accepted)", ref.URL)
		}
		v.store.incVerified()
		return true, nil
	case verifyTampered:
		v.store.incRejected()
		v.store.logRejectEvent(ref.URL, verr)
		return false, verr
	default: // verifyUnavailable
		if ref.SigURL != "" && len(v.keyring) == 0 && len(ref.HashURLs) == 0 {
			v.warnNoKeysOnce(ref.URL)
		} else {
			v.store.incUnverified()
			slog.Warn("advisory integrity data unavailable — stored unverified", "url", ref.URL)
			v.warnNoFetchOnce()
		}
		return false, nil
	}
}

// checkSignature fetches and verifies the OpenPGP detached signature over body.
// A missing/unfetchable signature is verifyUnavailable (transient); a present
// but invalid signature is verifyTampered. A valid signature from a since-
// expired key is verifyPass with expired=true.
func checkSignature(ctx context.Context, client *http.Client, keyring openpgp.EntityList, ref rolieEntryRef, body []byte) (verifyOutcome, bool, error) {
	sig, err := fetchCapped(ctx, client, ref.SigURL, maxSignatureBytes)
	if err != nil {
		return verifyUnavailable, false, nil
	}
	_, err = openpgp.CheckArmoredDetachedSignature(
		keyring, bytes.NewReader(body), bytes.NewReader(sig), nil,
	)
	switch {
	case err == nil:
		return verifyPass, false, nil
	case errors.Is(err, pgperrors.ErrKeyExpired), errors.Is(err, pgperrors.ErrSignatureExpired):
		// The cryptographic check already succeeded — these sentinels only mean
		// the signing key (or signature) has expired since. Providers rotate
		// keys but keep old advisories' original signatures (observed live on
		// Siemens ProductCERT), and the key still comes from the provider's
		// authoritative metadata over TLS. The library documents these two
		// errors as safely ignorable; everything else stays a hard reject.
		return verifyPass, true, nil
	default:
		return verifyTampered, false, fmt.Errorf("OpenPGP signature invalid (%s): %w", ref.SigURL, err)
	}
}

// checkHash compares body against the strongest advertised hash sidecar
// (sha512 preferred over sha256). A wrong digest is verifyTampered; if no
// sidecar could be fetched or parsed the result is verifyUnavailable.
func checkHash(ctx context.Context, client *http.Client, ref rolieEntryRef, body []byte) (verifyOutcome, error) {
	urls := append([]string(nil), ref.HashURLs...)
	for i, u := range urls {
		if strings.HasSuffix(u, ".sha512") && i != 0 {
			urls[0], urls[i] = urls[i], urls[0]
			break
		}
	}
	for _, hashURL := range urls {
		raw, err := fetchCapped(ctx, client, hashURL, maxHashFileBytes)
		if err != nil {
			continue // try the next sidecar; unreachable ≠ tampered
		}
		fields := strings.Fields(string(raw))
		if len(fields) == 0 {
			continue
		}
		want := strings.ToLower(fields[0])
		algo, digest := hashAlgoForURL(hashURL, want)
		if digest == nil {
			continue
		}
		if digest(body) != want {
			return verifyTampered, fmt.Errorf("%s mismatch against %s", algo, hashURL)
		}
		return verifyPass, nil
	}
	return verifyUnavailable, nil
}
