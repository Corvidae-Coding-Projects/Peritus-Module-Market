# Phase 13 HTTP/API and Phase 14 browser corpus

`vulnerable/` and `safe/` are interface-compatible copied Python services for the real
`linux.python-http-api.v1` laboratory. Both expose REST, live OpenAPI, GraphQL, WebSocket and
JSON-RPC routes plus browser pages for reflected, stored and DOM scripts, CSP, cookies, cross-origin
mutation, CSRF, validation, traditional/client-rendered crawl, download and upload. Only the
vulnerable twin admits the pinned protocol and browser/client-trust violations.

The host supplies the private Unix socket, copied state store and target-only canary. Corpus output
is untrusted; decisions come from module-captured protocol/browser effects and copied-state readback.

[Parent waypoint](../AGENTS.md).
