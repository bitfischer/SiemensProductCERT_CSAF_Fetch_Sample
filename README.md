# Siemens ProductCERT CSAF Fetch

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What is this?

Companies that make hardware and software publish **security advisories**
when a vulnerability is found in one of their products — a document saying
what's affected, how serious it is, and what to do about it. Siemens
ProductCERT publishes theirs in a standard machine-readable format called
**CSAF**, so tools can download and process them automatically instead of a
person reading each one by hand.

This project is a small, self-contained demo ("proof of concept") of exactly
that: a tool that downloads Siemens's ~800+ published advisories, checks each
one's cryptographic signature to make sure it's genuine and hasn't been
tampered with, and lays the results out in a simple web dashboard. It exists
to demonstrate one specific fix — see below — in a small, runnable form that
doesn't require any of the bigger system it was extracted from.

It's built like a typical small web app, with two parts working together:

- **Backend** — a Go program that talks to the Siemens servers, downloads
  and verifies the advisories, and exposes the results over a small JSON API.
- **Frontend** — a single web page (`web/index.html`) that runs in your
  browser, with a "Fetch now" button and tables that fill in live as the
  backend works.

**Tech stack:** the backend is written in [Go](https://go.dev/); the
frontend is one plain HTML/CSS/JavaScript file with no framework and no
build step. The two are shipped as a single binary (the frontend is embedded
into it) and can be packaged into a [Docker](https://www.docker.com/)
container, or run directly with just a Go installation — see
[Run](#run) below.

## How it works

A standalone CSAF/ROLIE fetch + verification pipeline, pointed at a single
feed: **Siemens ProductCERT**
(`https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json`).

It exists to demonstrate, in isolation, the fix for Siemens rate-limiting a
full fetch of its CSAF feed (~800+ advisories). The fix has two parts:

1. **Signature-preferred verification** (`verify.go`) — an OpenPGP detached
   signature proves both integrity and authenticity, which is strictly
   stronger than the accompanying SHA-256/512 hash sidecar. So when a
   signature is advertised and verifies, the redundant hash fetch is skipped
   entirely — halving the number of requests per advisory (document + hash +
   signature → document + signature).
2. **Bounded worker pool** (`rolie.go`, `rolieAdvisoryWorkers = 8`) —
   concurrency is capped rather than scaled up, since more parallel requests
   just provoke provider rate-limiting without going faster.

Tampering (a wrong hash/signature) is still always rejected before parsing;
an *unreachable* sidecar (rate-limited, transient error) is stored as
`unverified` rather than discarding a legitimate advisory.

This is **read-only and stateless**: it fetches, verifies, and parses
advisories into memory for inspection. There is no database — restarting the
container drops everything. It does not write anything back to
`cert-portal.siemens.com`.

## Screenshots

The bundled frontend (`web/index.html`) is a single static page with no
build step, served by the same Go binary as the API. It polls
`/api/status`, `/api/log`, `/api/advisories`, and `/api/cves` every 1.2s
while a fetch is running.

**Idle**, before the first fetch:

![Idle state — no fetch run yet](docs/screenshots/idle.png)

**Running**, mid-fetch against the live Siemens feed — the log streams
per-advisory signature outcomes as the bounded worker pool processes them,
while the stat tiles and tables update incrementally:

![Fetch in progress — live signature verification log, advisory and CVE tables filling in](docs/screenshots/running.png)

**Complete** — a full run against `cert-portal.siemens.com`: advisories,
and CVEs fetched and all verified via OpenPGP signature, zero rejected, zero
unverified:

![Fetch complete — 841 advisories verified, 5,387 CVEs, zero rejected/unverified](docs/screenshots/complete.png)

## Scope

This repository is a **deliberately narrow extraction**, not a general-purpose
CSAF client. It exists to isolate and demonstrate one fix in a reviewable,
runnable form — everything in it is scoped to that goal:

- **One feed, hardcoded.** The Siemens ProductCERT provider-metadata URL is a
  `const` in `main.go`. There is no config for adding other providers, no
  multi-tenant fetch, no scheduling — a fetch only ever happens when
  `POST /api/fetch` is called (manually, via the UI button, or by a script).
- **No persistence.** `store.go` is a mutex-guarded in-memory struct. Advisory
  and CVE data, and the fetch log, live only for the process lifetime; there
  is no database, no disk cache, no dedup across container restarts. A restart
  means the next fetch starts from scratch (a full ~800-advisory run, not
  incremental).
- **No write path to the provider.** Every request against
  `cert-portal.siemens.com` is a `GET`. The pipeline never authenticates,
  never uploads, never mutates anything upstream.
- **No auth, no multi-user state.** The HTTP API and UI are unauthenticated by
  design — this is meant to run locally or in a throwaway container for
  inspection, not to be exposed as a multi-tenant service.
- **Defense-in-depth included, but sized for this one path.** `safehttp.go`
  blocks SSRF via private/loopback/link-local dial targets and blocks a
  https→http redirect downgrade; `guard.go` caps every response size to what
  the Siemens feed's real documents look like (`maxAdvisoryBytes = 32 MiB`,
  etc.) and recovers panics per-worker so one malformed document can't take
  down a run. These guards are real and load-bearing, but their limits are
  tuned to a single known feed, not a hardened multi-provider ingestion
  service.
- **Parsing is intentionally partial.** `parse.go` extracts what the frontend
  needs (tracking ID, title, severity, CVEs, products, references) from CSAF
  2.0 JSON — it is not a full CSAF schema validator or a complete
  ingestion/normalization pipeline for a downstream vulnerability database.

In short: this is the smallest correct, runnable slice of a larger CSAF
ingestion pipeline that reproduces and fixes one specific problem (Siemens
ProductCERT rate-limiting a full feed fetch), stripped of everything
(persistence, multi-provider config, auth, scheduling) that isn't needed to
demonstrate that fix.

## Components

| File | Purpose |
|---|---|
| `safehttp.go` | SSRF-safe HTTP client (blocks private/loopback/link-local dial targets, blocks https→http redirect downgrade) |
| `guard.go` | Size-capped reads, panic recovery per worker/run |
| `verify.go` | OpenPGP signature + hash verification, tampered-vs-unavailable policy, the rate-limiting fix |
| `parse.go` | Pure CSAF JSON → CVE/Advisory parsing |
| `rolie.go` | Provider-metadata + ROLIE feed walk, bounded worker pool, conditional-GET incremental fetch |


## Run

### With Docker

```bash
docker compose up --build
```

Then open <http://localhost:8080> and click **Fetch now**. A full run
(~800 advisories, ~5,000 CVEs) takes a few seconds. A second click re-fetches
incrementally — unchanged advisories are skipped via the ROLIE feed's
conditional GET (`ETag`/`Last-Modified`) and per-entry `updated` timestamps.

### Without Docker

Requires [Go](https://go.dev/dl/) 1.25 or newer (see `go.mod`); no other
dependencies are needed — the frontend is embedded into the binary via
`go:embed` (`main.go`), so there's nothing to separately build or serve.

Run it in place, no build step:

```bash
go run .
```

Or build a standalone binary and run that (matches what the Dockerfile does,
just without the container):

```bash
go build -o spcert-fetch .
./spcert-fetch
```

Either way it listens on `:8080` by default; open <http://localhost:8080> and
click **Fetch now** as above. Set `PORT` to use a different port:

```bash
PORT=9090 go run .
```

## API

- `POST /api/fetch` — trigger a fetch; `409` if one is already running
- `GET /api/status` — running state, live progress, verified/rejected/unverified counters
- `GET /api/log` — fetch trail (newest first)
- `GET /api/advisories` — parsed advisories
- `GET /api/cves` — parsed CVEs

## License

Licensed under the MIT License. See [LICENSE](LICENSE).
