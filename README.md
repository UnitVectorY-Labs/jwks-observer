# jwks-observer

Observes and records changes to public OIDC metadata and JWKS for services listed in the jwks-catalog.

## Overview

The **jwks-observer** reads the list of services from the jwks-catalog (either from the default upstream URL or a user-supplied catalog), then for each service it:

1.	Fetches the OIDC configuration URL and validates that it contains the required top-level fields (issuer, jwks_uri).
2.	Fetches the JWKS URL and validates that it contains the keys array.
3.	Records response metadata (stable HTTP headers, status codes, and any error messages).
4.	Tracks each individual JWK by KID, stamping when it was first observed and when it was last observed.
5.	Outputs all of the above into a structured directory under data/, committing diffs into Git so that you can see how keys and configurations evolve over time.

This is scheduled to run once a day with the updated results automatically committed to this repository.

## Generated Folder Structure

```
data/
└── <service-id>/
    ├── jwks.json               # pretty-printed JWKS response
    ├── jwks-headers.json       # selected HTTP headers from the JWKS response
    ├── jwks-observed.json      # timestamps of when JWKS keys were first and last observed 
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

### `jwks.json`

- Contents: the raw JWKS object as returned by the server (must include a top-level keys array).
- Formatting: pretty-printed, two-space indent, keys sorted. This does not directly represent the payloadexact payload returned by the server, rather the content that was observed at the time of the fetch.

```json
{
  "keys": [
    {
      "e": "AQAB",
      "kty": "RSA",
      "kid": "ABC123",
      "n": "0vx7agoebGcQSuuPiL..."
    }
  ]
}
```

### `oidc-headers.json` & `jwks-headers.json`

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
- Contents: map of all seen KIDs → first_observed (RFC3339 UTC) and optional last_observed when a key disappears.
- Purpose: This file tracks the history of each key by its KID, allowing you to see when keys were first observed and when they were last observed (if they are no longer present in the current JWKS).

```json
{
  "ABC123": {
    "first_observed": "2025-05-01T08:00:00Z"
  },
  "XYZ789": {
    "first_observed": "2025-05-10T12:30:00Z",
    "last_observed":  "2025-05-20T15:45:00Z"
  }
}
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
