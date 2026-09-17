# Security Policy

## Scope

This repository is a small, self-contained **demo / proof-of-concept**
extracted from a larger internal pipeline (see the [README](README.md#scope)
for the full rationale). It fetches, cryptographically verifies, and displays
publicly published Siemens ProductCERT CSAF advisories. It is:

- **Read-only** against `cert-portal.siemens.com` — it never authenticates,
  uploads, or mutates anything upstream.
- **Unauthenticated and stateless** by design — meant to run locally or in a
  throwaway container, not as an exposed multi-tenant service.

Given that scope, the security issues most relevant to this project are
things like:

- A way to make the fetcher accept a tampered/unsigned advisory as verified
  (see `verify.go`).
- A way to bypass the SSRF protections in `safehttp.go` (e.g. redirecting to
  a private/loopback/link-local address).
- A way to bypass the size/response guards in `guard.go` to cause excessive
  memory use or a crash from a malicious or malformed feed response.
- Cross-site scripting or similar issues in the bundled frontend
  (`web/index.html`), e.g. via unescaped advisory data.

Please do **not** open reports for things that are out of scope by design and
already documented in the README, such as: no authentication, no
persistence/database, or the API being unauthenticated on `:8080`.

## Reporting a Vulnerability

This is a personal demo project, not an official Siemens product or an
officially supported Siemens repository — please do **not** report issues
found here to Siemens ProductCERT.

If you find a security issue in this code, please report it privately using
[GitHub's private vulnerability reporting](../../security/advisories/new)
for this repository, rather than opening a public issue. If that isn't
available, open a regular issue with minimal detail and ask for a private
channel to share the rest.

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce, or a minimal proof of concept.
- The affected file(s)/function(s), if known.

There is no bug bounty associated with this project. As a best-effort,
unpaid open-source project, there's no guaranteed response time, but
reports will be looked at and, if valid, fixed and credited.

## Reporting Issues in Siemens Products

If you found a vulnerability in an actual Siemens product (not in this demo
code), report it to Siemens ProductCERT directly, not here:
<https://www.siemens.com/global/en/products/services/cert.html>
