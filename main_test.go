package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
)

func readHeaders(t *testing.T, path string) ([]byte, map[string]string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	return b, got
}

func TestWriteHeadersPresence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "headers.json")
	hdrs := http.Header{
		"x-auth0-l":                 {"0.123"},
		"X-AUTH0-REQUESTID":         {"request-one", "request-two"},
		"X-Okta-Request-Id":         {""},
		"x-ms-ests-server":          {"version region"},
		"x-sfdc-edge-cache":         {"MISS"},
		"X-SFDC-REQUEST-ID":         {"request-one"},
		"x-forgerock-transactionid": {"transaction-one"},
		"X-Auth0-Unknown":           {"not allowlisted"},
		"X-Amzn-Requestid":          {"generic infrastructure"},
		"Set-Cookie":                {"session=secret"},
		"Date":                      {"changes every crawl"},
		"Content-Type":              {"application/json"},
		"Cache-Control":             {"public, max-age=123"},
		"Via":                       {"1.1 abc.cloudfront.net (CloudFront)"},
		"Content-Security-Policy":   {"script-src 'nonce-abc123'"},
		"Strict-Transport-Security": {"max-age=31536000"},
		"Server":                    {"nginx"},
	}
	want := map[string]string{
		"X-Auth0-L": "[present]", "X-Auth0-RequestId": "[present]",
		"X-Okta-Request-Id": "[present]", "X-Ms-Ests-Server": "[present]",
		"X-Sfdc-Edge-Cache": "[present]", "X-Sfdc-Request-Id": "[present]",
		"X-ForgeRock-TransactionId": "[present]",
		"Content-Type":              "application/json", "Cache-Control": "public, max-age=[placeholder]",
		"Via":                       "1.1 [placeholder].cloudfront.net (CloudFront)",
		"Content-Security-Policy":   "script-src 'nonce-[placeholder]'",
		"Strict-Transport-Security": "max-age=31536000", "Server": "nginx",
	}
	writeHeaders(path, hdrs)
	first, got := readHeaders(t, path)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("headers = %#v; want %#v", got, want)
	}
	for _, key := range []string{"x-auth0-l", "X-AUTH0-REQUESTID", "X-Okta-Request-Id", "x-ms-ests-server", "x-sfdc-edge-cache", "X-SFDC-REQUEST-ID", "x-forgerock-transactionid"} {
		hdrs[key] = []string{"a completely different value"}
	}
	writeHeaders(path, hdrs)
	second, _ := readHeaders(t, path)
	if !bytes.Equal(first, second) {
		t.Fatalf("changing presence-only values changed output:\n%s\n%s", first, second)
	}
	// A successful response without hints clears previous evidence, including when
	// headers have been stripped by a proxy or the endpoint is custom-built.
	writeHeaders(path, nil)
	_, got = readHeaders(t, path)
	if len(got) != 0 {
		t.Fatalf("stale headers retained: %#v", got)
	}
}

func TestCrawlCollectsPresenceForAllEndpointTypes(t *testing.T) {
	var attempt atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/catalog" {
			fmt.Fprintf(w, "services:\n  - id: example\n    openid-configuration: %s/oidc\n    oauth-authorization-server: %s/oauth\n    jwks_uri: %s/redirect\n", server.URL, server.URL, server.URL)
			return
		}
		if r.URL.Path == "/redirect" {
			w.Header().Set("X-Okta-Request-Id", "redirect-only")
			http.Redirect(w, r, "/jwks", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if attempt.Load() < 2 {
			w.Header().Set("X-Auth0-L", fmt.Sprint(attempt.Load()))
		}
		switch r.URL.Path {
		case "/oidc":
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, server.URL, server.URL+"/redirect")
		case "/oauth":
			fmt.Fprintf(w, `{"issuer":%q}`, server.URL)
		case "/jwks":
			fmt.Fprint(w, `{"keys":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	binary := filepath.Join(dir, "observer")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	outDir := filepath.Join(dir, "data")
	previous := map[string][]byte{}
	for i := range int32(3) {
		attempt.Store(i)
		if out, err := exec.Command(binary, "-catalog", server.URL+"/catalog", "-out", outDir).CombinedOutput(); err != nil {
			t.Fatalf("crawl: %v\n%s", err, out)
		}
		for _, filename := range []string{"oidc-headers.json", "oauth-authorization-server-headers.json", "jwks-headers.json"} {
			b, got := readHeaders(t, filepath.Join(outDir, "example", filename))
			want := map[string]string{"Content-Type": "application/json"}
			if i < 2 {
				want["X-Auth0-L"] = "[present]"
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("crawl %d %s = %#v; want %#v", i, filename, got, want)
			}
			if i == 1 && !bytes.Equal(b, previous[filename]) {
				t.Fatalf("%s changed between crawls", filename)
			}
			previous[filename] = b
		}
	}
}
