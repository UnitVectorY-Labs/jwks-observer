[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![Work In Progress](https://img.shields.io/badge/Status-Work%20In%20Progress-yellow)](https://guide.unitvectorylabs.com/bestpractices/status/#work-in-progress) 

# jwks-observer

Observes and records changes to public OIDC metadata and JWKS for services listed in the jwks-catalog.

## Overview

The **jwks-observer** reads the list of services from the jwks-catalog (either from the default upstream URL or a user-supplied catalog), then for each service it:

1.	Fetches the OIDC configuration URL and validates that it contains the required top-level fields (issuer, jwks_uri).
2.	Fetches the OAuth 2.0 Authorization Server Metadata URL, when configured, and validates the RFC 8414-required `issuer` field.
3.	Fetches the JWKS URL and validates that it contains the keys array.
4.	Records response metadata (stable HTTP headers, status codes, and any error messages).
5.	Tracks each individual JWK by KID, stamping when it was first observed and when it was last observed. Individual keys are stored in the `keys/` directory.
6.	Outputs all of the above into a structured directory under data/, committing diffs into Git so that you can see how keys and configurations evolve over time.

This is scheduled to run once a day with the updated results automatically committed to this repository.

## Generated Folder Structure

```
data/
└── <service-id>/
    ├── jwks-headers.json                         # selected HTTP headers from the JWKS response
    ├── jwks-observed.json                        # alphabetically sorted array of active JWKS key IDs (KIDs)
    ├── keys/
    │   ├── <kid1>.json                       # JWKS keys including historical keys
    │   ├── <kid2>.json
    │   └── …
    ├── oidc.json                                 # pretty-printed OIDC config
    ├── oidc-headers.json                         # selected HTTP headers from the OIDC response
    ├── oauth-authorization-server.json           # RFC 8414 metadata, when configured
    ├── oauth-authorization-server-headers.json   # selected metadata response headers
    └── status.json                               # last HTTP status codes and errors
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

- Contents: selected response headers mapped as Header-Name: value (the same format applies to `oidc-headers.json` and `oauth-authorization-server-headers.json`).
  - Content-Type
  - Cache-Control
  - Server
  - Via
  - Content-Security-Policy
  - Strict-Transport-Security

```json
{
  "Cache-Control": "public, max-age=[placeholder]",
  "Content-Type": "application/json; charset=UTF-8",
  "Server": "nginx/1.18.0"
}
```

### Provider header evidence

The three `*-headers.json` files also record the following allowlisted headers
with the literal string `[present]`, **never their response values**:

| Header (stored spelling) | Potential provider | Evidence source |
| --- | --- | --- |
| `X-Auth0-L` | Auth0 | [Auth0 discovery endpoint](https://auth.auth0.com/.well-known/openid-configuration) |
| `X-Auth0-RequestId` | Auth0 | [Auth0 discovery endpoint](https://auth.auth0.com/.well-known/openid-configuration) |
| `X-Okta-Request-Id` | Okta | [Okta request debugging documentation](https://developer.okta.com/docs/reference/core-okta-api/#request-debugging) |
| `X-Ms-Ests-Server` | Microsoft Entra ID | [Microsoft discovery endpoint](https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration) |
| `X-Sfdc-Edge-Cache` | Salesforce infrastructure | [AbbVie discovery endpoint](https://id.abbvie.com/.well-known/openid-configuration) |
| `X-Sfdc-Request-Id` | Salesforce infrastructure | [AbbVie discovery endpoint](https://id.abbvie.com/.well-known/openid-configuration) |
| `X-ForgeRock-TransactionId` | ForgeRock / Ping Identity platform | [Ping request tracing documentation](https://docs.pingidentity.com/pingoneaic/tenants/audit-debug-logs-pull.html); [Computershare discovery endpoint](https://auth.computershare.com/am/oauth2/.well-known/openid-configuration) |

These headers were observed on the corresponding public discovery endpoints
on 2026-09-23, including [Okta's endpoint](https://auth.okta.com/.well-known/openid-configuration).
This is an initial evidence allowlist, not exhaustive provider coverage or a guarantee
that these headers will always be emitted.

For example, an Auth0 response can produce:

```json
{
  "Content-Type": "application/json",
  "X-Auth0-L": "[present]",
  "X-Auth0-RequestId": "[present]"
}
```

Matching is case-insensitive, includes empty-valued headers, and emits one fixed
key per header regardless of casing, repeated values, or ordering. Changing
latencies, request IDs, and deployment versions therefore do not change this
evidence. No timestamps or provider labels are added. An absent header is omitted;
its disappearance on a subsequent successful crawl removes the marker.

These are hints for future analysis, not proof of the hosting provider. Proxies
can strip or inject headers, services can implement their own OAuth endpoints,
and absence does not rule out any provider. Generic infrastructure headers such
as `X-Amzn-RequestId`, `X-Ms-Request-Id`, or `CF-Ray` are not collected as provider
hints: they do not distinguish an identity product from other services on the
same infrastructure. The `X-Sfdc-*` markers indicate Salesforce's edge, which
also serves non-identity products; they alone do not establish that Salesforce
provides the underlying identity service. Existing discovery documents preserve
issuer and endpoint URLs for future analysis of providers without distinctive
headers.

As with existing header values, evidence is saved only for HTTP 200 responses
whose JSON passes endpoint validation, from the final response after redirects.
Intermediate redirect headers are not merged into endpoint evidence. Failed
fetches retain the previous successful header file; consult `status.json` to
check whether the latest fetch succeeded. The new markers avoid value churn;
actual changes in header presence still produce diffs, and existing stable-value
header collection and normalization remain unchanged.

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
