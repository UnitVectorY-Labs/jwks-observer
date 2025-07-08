// main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultCatalogURL = "https://raw.githubusercontent.com/UnitVectorY-Labs/jwks-catalog/main/data/services.yaml"

// Service represents an entry in the JWKS catalog.
type Service struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	OIDCURI string `yaml:"openid-configuration"`
	JWKSURI string `yaml:"jwks_uri"`
}

// Catalog holds the list of services.
type Catalog struct {
	Services []Service `yaml:"services"`
}

// statusEntry captures the last HTTP status for a fetch.
type statusEntry struct {
	URI        string `json:"uri,omitempty"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error,omitempty"`
}

// KeyObservation tracks when a JWK was first and last seen.
// This struct is now primarily for the individual key files.
type KeyObservation struct {
	FirstObserved string `json:"first_observed"`
	LastObserved  string `json:"last_observed,omitempty"`
}

var httpClient = &http.Client{Timeout: 15 * time.Second}
var stableHeaderKeys = []string{
	"Content-Type",
	"Cache-Control",
	"Server",
	"Via",
	"Content-Security-Policy",
}
var cacheControlRegex = regexp.MustCompile(`(max-age=)(\d+)`)
var viaRegex = regexp.MustCompile(`(1\.1 )([a-zA-Z0-9_\.-]+)(\.cloudfront\.net \(CloudFront\))`) 
var cspNonceRegex = regexp.MustCompile(`('nonce-)([a-zA-Z0-9_=\\-]+)(')`) 

// jwksMismatches stores services with mismatched JWKS URIs
var jwksMismatches = struct {
	sync.Mutex
	Services []string
}{}

func main() {
	outDir := flag.String("out", "data", "output directory for JSON, headers, status, and observed keys")
	catalogURL := flag.String("catalog", "", "URL of services.yaml (defaults to upstream)")
	flag.Parse()

	ctx := context.Background()
	catalog, err := fetchCatalog(ctx, *catalogURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to fetch catalog: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output dir: %v\n", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	for _, svc := range catalog.Services {
		svc := svc
		wg.Add(1)
		go func() {
			defer wg.Done()

			dir := filepath.Join(*outDir, svc.ID)
			keysDir := filepath.Join(dir, "keys")
			os.MkdirAll(keysDir, 0o755)

			// track statuses
			statuses := map[string]statusEntry{}

			// 1) Fetch OIDC config
			if svc.OIDCURI != "" {
				oidcObj, prettyOIDC, hdrsOIDC, codeOIDC, errOIDC :=
					fetchAndValidateJSON(svc.OIDCURI, []string{"issuer", "jwks_uri"})
				if errOIDC != nil {
					statuses["oidc"] = statusEntry{URI: svc.OIDCURI, StatusCode: codeOIDC, Error: errOIDC.Error()}
					fmt.Fprintf(os.Stderr, "[%s] OIDC crawl failed: %v\n", svc.ID, errOIDC)
				} else {
					statuses["oidc"] = statusEntry{URI: svc.OIDCURI, StatusCode: codeOIDC}
					writeFile(filepath.Join(dir, "oidc.json"), prettyOIDC)
					writeHeaders(filepath.Join(dir, "oidc-headers.json"), hdrsOIDC)
					
					// Check if the JWKS URI in OIDC matches the configured one
					if oidcMap, ok := oidcObj.(map[string]interface{}); ok {
						if discoveredJWKSURI, ok := oidcMap["jwks_uri"].(string); ok && discoveredJWKSURI != "" {
							if svc.JWKSURI != "" && svc.JWKSURI != discoveredJWKSURI {
								// Add to mismatches list
								jwksMismatches.Lock()
								jwksMismatches.Services = append(jwksMismatches.Services, svc.ID)
								jwksMismatches.Unlock()
								
								fmt.Fprintf(os.Stdout, "[%s] JWKS URI mismatch - Configured: %s, Discovered: %s\n", 
									svc.ID, svc.JWKSURI, discoveredJWKSURI)
							}
						}
					}
				}
			} else {
				fmt.Fprintf(os.Stdout, "[%s] Skipping OIDC fetch: URL not set\n", svc.ID)
			}

			// 2) Fetch JWKS
			if svc.JWKSURI != "" {
				parsedJWKS, _, hdrsJWKS, codeJWKS, errJWKS :=
					fetchAndValidateJSON(svc.JWKSURI, []string{"keys"})
				if errJWKS != nil {
					statuses["jwks"] = statusEntry{URI: svc.JWKSURI, StatusCode: codeJWKS, Error: errJWKS.Error()}
					fmt.Fprintf(os.Stderr, "[%s] JWKS crawl failed: %v\n", svc.ID, errJWKS)
				} else {
					statuses["jwks"] = statusEntry{URI: svc.JWKSURI, StatusCode: codeJWKS}
					writeHeaders(filepath.Join(dir, "jwks-headers.json"), hdrsJWKS)

					// 3) Update observed keys
					updateObservedKeys(keysDir, dir, parsedJWKS)
				}
			} else {
				fmt.Fprintf(os.Stdout, "[%s] Skipping JWKS fetch: URL not set\n", svc.ID)
			}

			// 4) Write status.json
			if b, err := json.MarshalIndent(statuses, "", "  "); err != nil {
				fmt.Fprintf(os.Stderr, "[%s] status.json marshal error: %v\n", svc.ID, err)
			} else if err := os.WriteFile(filepath.Join(dir, "status.json"), b, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "[%s] status.json write error: %v\n", svc.ID, err)
			}
		}()
	}
	wg.Wait()
	
	// Write the JWKS mismatches to a file
	fmt.Println("Processing JWKS URI mismatches...")
	writeJWKSMismatches(*outDir)
	fmt.Println("Crawl complete.")
}

// fetchCatalog retrieves and parses the YAML catalog.
func fetchCatalog(ctx context.Context, url string) (*Catalog, error) {
	if url == "" {
		url = defaultCatalogURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog fetch failed: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var c Catalog
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// fetchAndValidateJSON fetches a URL, ensures HTTP 200, valid JSON, and required fields.
// Returns the parsed JSON (as interface{}), a pretty-printed []byte,
// the response headers, the HTTP status code, and an error if any.
func fetchAndValidateJSON(url string, requiredFields []string) (
	parsed interface{}, pretty []byte, hdrs http.Header, statusCode int, err error,
) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	defer resp.Body.Close()
	statusCode = resp.StatusCode

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, resp.Header, statusCode, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, resp.Header, statusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, nil, resp.Header, statusCode, fmt.Errorf("invalid JSON: %w", err)
	}

	obj, ok := parsed.(map[string]interface{})
	if !ok {
		return nil, nil, resp.Header, statusCode, fmt.Errorf("JSON is not an object")
	}
	for _, f := range requiredFields {
		if _, found := obj[f]; !found {
			return nil, nil, resp.Header, statusCode, fmt.Errorf("missing required field %q", f)
		}
	}

	pretty, err = json.MarshalIndent(parsed, "", "  ")
	return parsed, pretty, resp.Header, statusCode, err
}

// writeFile writes data to path, reporting any errors.
func writeFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write error %s: %v\n", path, err)
	}
}

// writeHeaders extracts stable headers and writes them as JSON.
func writeHeaders(path string, hdrs http.Header) {
	meta := make(map[string]string, len(stableHeaderKeys))
	for _, k := range stableHeaderKeys {
		if v := hdrs.Get(k); v != "" {
			switch k {
			case "Cache-Control":
				v = cacheControlRegex.ReplaceAllString(v, "${1}[placeholder]")
			case "Via":
				v = viaRegex.ReplaceAllString(v, "${1}[placeholder]${3}")
			case "Content-Security-Policy":
				v = cspNonceRegex.ReplaceAllString(v, "${1}[placeholder]${3}")
			}
			meta[k] = v
		}
	}
	if b, err := json.MarshalIndent(meta, "", "  "); err != nil {
		fmt.Fprintf(os.Stderr, "headers marshal error %s: %v\n", path, err)
	} else if err := os.WriteFile(path, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "headers write error %s: %v\n", path, err)
	}
}

// writeJWKSMismatches writes the list of services with mismatched JWKS URIs to a JSON file.
func writeJWKSMismatches(outDir string) {
	jwksMismatches.Lock()
	defer jwksMismatches.Unlock()
	
	// Sort the service names alphabetically
	sort.Strings(jwksMismatches.Services)
	
	// Create the JSON file
	mismatchesPath := filepath.Join(outDir, "jwks_mismatch.json")
	
	// Write the sorted list to the file
	if b, err := json.MarshalIndent(jwksMismatches.Services, "", "  "); err != nil {
		fmt.Fprintf(os.Stderr, "jwks_mismatch.json marshal error: %v\n", err)
	} else if err := os.WriteFile(mismatchesPath, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "jwks_mismatch.json write error: %v\n", err)
	} else {
		fmt.Printf("JWKS URI mismatches found: %d\n", len(jwksMismatches.Services))
	}
}

// updateObservedKeys reads (or creates) jwks-observed.json, updates first/last observed times,
// writes per-key files, and writes back jwks-observed.json.
// jwks-observed.json will now be an array of active KIDs.
func updateObservedKeys(keysDir, serviceDir string, parsedJWKS interface{}) {
	obsPath := filepath.Join(serviceDir, "jwks-observed.json")

	// load existing observations from individual key files to preserve first_observed dates
	existingKeyFiles, _ := filepath.Glob(filepath.Join(keysDir, "*.json"))
	obsData := make(map[string]KeyObservation)
	for _, keyFile := range existingKeyFiles {
		kid := filepath.Base(keyFile[:len(keyFile)-len(filepath.Ext(keyFile))])
		if data, err := os.ReadFile(keyFile); err == nil {
			var keyData struct {
				FirstObserved string `json:"first_observed"`
				LastObserved  string `json:"last_observed,omitempty"`
			}
			if json.Unmarshal(data, &keyData) == nil {
				obsData[kid] = KeyObservation{FirstObserved: keyData.FirstObserved, LastObserved: keyData.LastObserved}
			}
		}
	}

	// extract current keys
	obj := parsedJWKS.(map[string]interface{})
	rawKeys := obj["keys"].([]interface{})
	now := time.Now().UTC().Format(time.RFC3339)

	currentKidsMap := make(map[string]struct{})
	activeKidsList := []string{}

	for _, raw := range rawKeys {
		keyObj := raw.(map[string]interface{})
		kid, _ := keyObj["kid"].(string)
		currentKidsMap[kid] = struct{}{}
		activeKidsList = append(activeKidsList, kid)

		entry, seen := obsData[kid]
		if !seen || entry.FirstObserved == "" { // If new or first_observed was missing
			entry.FirstObserved = now
		}
		// Clear any previous "last_observed" if it reappeared
		entry.LastObserved = ""
		obsData[kid] = entry

		// write the individual key file
		// Ensure first_observed is part of the key object before marshalling
		keyWithTimestamps := make(map[string]interface{})
		for k, v := range keyObj {
			keyWithTimestamps[k] = v
		}
		keyWithTimestamps["first_observed"] = entry.FirstObserved
		// Do not write last_observed if it's empty

		if kb, err := json.MarshalIndent(keyWithTimestamps, "", "  "); err != nil {
			fmt.Fprintf(os.Stderr, "key marshal error %s/%s.json: %v\n", keysDir, kid, err)
		} else {
			os.WriteFile(filepath.Join(keysDir, kid+".json"), kb, 0o644)
		}
	}

	// mark any keys that disappeared by adding last_observed to their individual files
	for kid, entry := range obsData {
		if _, ok := currentKidsMap[kid]; !ok && entry.LastObserved == "" {
			entry.LastObserved = now
			obsData[kid] = entry // Update obsData for consistency, though it's not directly saved anymore

			// update the individual key file with last_observed
			keyFilePath := filepath.Join(keysDir, kid+".json")
			if data, err := os.ReadFile(keyFilePath); err == nil {
				var keyMap map[string]interface{}
				if json.Unmarshal(data, &keyMap) == nil {
					keyMap["last_observed"] = now
					if kb, err := json.MarshalIndent(keyMap, "", "  "); err == nil {
						os.WriteFile(keyFilePath, kb, 0o644)
					}
				}
			}
		}
	}

	// Sort the active KIDs alphabetically
	sort.Strings(activeKidsList)

	// write back the jwks-observed.json as a sorted array of active KIDs
	if b, err := json.MarshalIndent(activeKidsList, "", "  "); err != nil {
		fmt.Fprintf(os.Stderr, "observed marshal error %s: %v\n", obsPath, err)
	} else if err := os.WriteFile(obsPath, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "observed write error %s: %v\n", obsPath, err)
	}
}