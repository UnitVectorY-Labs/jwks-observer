[![License](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/licenses/MIT) [![Work In Progress](https://img.shields.io/badge/Status-Work%20In%20Progress-yellow)](https://guide.unitvectorylabs.com/bestpractices/status/#work-in-progress)

# jwks-observer

Observes and records changes to public OIDC metadata and JWKS for services listed in the jwks-catalog.

## Overview

The **jwks-observer** reads the list of services from the jwks-catalog (either from the default upstream URL or a user-supplied catalog), then for each service it:

1.	Fetches the OIDC configuration URL and validates that it contains the required top-level fields (issuer, jwks_uri).
2.	Fetches the JWKS URL and validates that it contains the keys array.
3.	Records response metadata (stable HTTP headers, status codes, and any error messages).
4.	Tracks each individual JWK by KID, stamping when it was first observed and when it was last observed. Individual keys are stored in the `keys/` directory.
5.	Outputs all of the above into a structured directory under data/, committing diffs into Git so that you can see how keys and configurations evolve over time.

This is scheduled to run once a day with the updated results automatically committed to this repository.

## Generated Folder Structure

```
data/
└── <service-id>/
    ├── jwks-headers.json       # selected HTTP headers from the JWKS response
    ├── jwks-observed.json      # alphabetically sorted array of active JWKS key IDs (KIDs)
    └── keys/
        ├── <kid1>.json         # JWKS keys including historical keys
        ├── <kid2>.json
        └── …      
    ├── oidc.json               # pretty-printed OIDC config
    ├── oidc-headers.json       # selected HTTP headers from the OIDC response
    ├── status.json             # last HTTP status codes and errors for oidc/jwks          
```

- Each <service-id> directory corresponds to the id field in your catalog.
- The application will create missing directories as needed and update only the files that have changed.

## File Type & JSON Structure

### `oidc.json`

- Contents: full OIDC discovery document (e.g. issuer, jwks_uri, authorization_endpoint, etc.) varies by service.
- Formatting: pretty-printed, two-space indent, object keys sorted alphabetically. This does not directly represent the payloadexact payload returned by the server, rather the content that was observed at the time of the fetch.

```json
{
  "authorization_endpoint": "https://login.example.com/authorize",
  "issuer": "https://login.example.com",
  "jwks_uri": "https://login.example.com/.well-known/jwks.json",
  "token_endpoint": "https://login.example.com/token"
}
```

### `jwks-headers.json`

- Contents: subset of “stable” response headers mapped as Header-Name: value.
  - Content-Type
  - Cache-Control
  - Server
  - Via
  - Content-Security-Policy

```json
{
  "Cache-Control": "public, max-age=3600",
  "Content-Type": "application/json; charset=UTF-8",
  "Server": "nginx/1.18.0"
}
```

### `status.json`

- Contents: status of the most recent fetch for OIDC and JWKS endpoints including the URLs that were used in the request.
- Purpose: This file captures the HTTP status codes and any errors encountered during the fetch operations, allowing you to quickly see if there were issues with the OIDC or JWKS endpoints.

```json
{
  "oidc": { 
    "url": "https://login.example.com/.well-known/openid-configuration",
    "status_code": 200 
  },
  "jwks": { 
    "url": "https://login.example.com/.well-known/jwks.json",
    "status_code": 500,
    "error": "HTTP 500" 
  }
}
```

### `jwks-observed.json`
- Contents: an alphabetically sorted JSON array of active KIDs (Key IDs) from the JWKS endpoint.
- Purpose: This file lists the KIDs that are currently present in the JWKS, allowing for a quick overview of active keys. Timestamps for when keys are first/last observed are tracked within individual key files in the `keys/` directory.

```json
[
  "ABC123",
  "DEF456",
  "XYZ789"
]
```

### `keys/<kid>.json`

- Contents: the raw single-JWK object
- Purpose: This includes historical keys that have been observed, even if they are no longer present in the current JWKS.

```json
{
  "e": "AQAB",
  "kty": "RSA",
  "kid": "ABC123",
  "n": "0vx7agoebGcQSuuPiL...",
  "first_observed": "2025-05-01T08:00:00Z"
}
```
