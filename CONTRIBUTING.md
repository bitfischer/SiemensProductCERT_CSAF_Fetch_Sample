# Contributing

Thanks for your interest in this project. It's a deliberately small,
narrowly-scoped demo (see [README § Scope](README.md#scope)) — please read
that section before proposing anything that grows it into a general-purpose
CSAF client. Changes that keep it small, correct, and reviewable are welcome;
changes that add config for other providers, persistence, auth, or
scheduling are likely out of scope for this repo, even if they'd be
reasonable for the larger system it was extracted from.

## Before you start

For anything more than a small fix, please open an issue first to discuss
the change. This avoids spending effort on a PR that doesn't fit the
project's scope.

## Development

Requires [Go](https://go.dev/dl/) 1.25 or newer.

```bash
go run .          # run locally, no build step
go build ./...    # build
go vet ./...      # static checks
gofmt -l .         # check formatting (should print nothing)
```

There is no Docker requirement for development — `docker compose up --build`
is only needed to reproduce the packaged deployment.

## Guidelines

- Keep changes focused and minimal — this codebase favors a few clear files
  over abstraction (see the [Components](README.md#components) table).
- Run `gofmt` on any Go files you touch.
- Explain the *why* in commit messages and PR descriptions, not just the
  *what*.
- If you're changing behavior around signature verification
  (`verify.go`) or the SSRF/size guards (`safehttp.go`, `guard.go`), call
  that out explicitly in the PR — these are the security-relevant paths.
- The frontend (`web/index.html`) is intentionally a single file with no
  build step or framework; please keep it that way rather than introducing
  a bundler or dependency.

## Reporting bugs

Open a GitHub issue with steps to reproduce. For security-relevant bugs,
see [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
