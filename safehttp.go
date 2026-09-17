// Copyright (c) 2026 Florian Fischer
//
// Use of this source code is governed by the MIT license found in the
// LICENSE file in the project root.

// safehttp.go — SSRF-safe HTTP client. Every outbound fetch of a feed URL
// must go through newSafeHTTPClient so the connection is refused if the *resolved*
// destination is a private/loopback/link-local address. The check runs in
// net.Dialer.Control — after DNS resolution, before the socket connects — so
// it closes the validate-then-fetch TOCTOU / DNS-rebinding gap and applies to
// every redirect hop, not just the first request.
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8",     // "this host on this network" (RFC 1122) — 0.0.0.0 routes to localhost on some stacks
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local / cloud metadata (AWS IMDSv1, GCP, Azure)
		"100.64.0.0/10",  // shared address space (RFC 6598)
		"::/128",         // unspecified address
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// blockPrivateDialControl is a net.Dialer.Control hook that refuses to connect
// to a private, loopback, or link-local address. address is the concrete
// resolved "ip:port" the dialer is about to connect to, so this cannot be
// bypassed by DNS rebinding or a redirect to an internal host.
func blockPrivateDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf guard: invalid dial address %q", address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf guard: unparseable dial address %q", host)
	}
	if isPrivateIP(ip) {
		return fmt.Errorf("ssrf guard: refusing to connect to non-public address %s", host)
	}
	return nil
}

func safeTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   blockPrivateDialControl,
		}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// newSafeHTTPClient returns an *http.Client that will not connect to private,
// loopback, or link-local addresses. timeout bounds the whole request; the
// guard applies to the initial request and every redirect.
func newSafeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     safeTransport(),
		CheckRedirect: checkFeedRedirect,
	}
}

// checkFeedRedirect caps redirect chains and refuses to let a fetch that
// started on https be redirected to plain http.
func checkFeedRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("feedguard: too many redirects (%d)", len(via))
	}
	if req.URL.Scheme != "https" && via[0].URL.Scheme == "https" {
		return fmt.Errorf("feedguard: redirect downgrade to %s rejected", req.URL.Scheme)
	}
	return nil
}
