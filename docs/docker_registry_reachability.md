# Docker Registry V2 reachability criterion

The Distribution Registry HTTP API V2 specification defines `GET /v2/` as its version check. HTTP 200 confirms the V2 API. HTTP 401 is also an expected response when authentication is required: the client follows the `WWW-Authenticate` challenge. For either 200 or 401, the specification says the response should identify `Docker-Distribution-API-Version: registry/2.0`.

Accordingly, this harness separates transport success from application status. Only the Docker Registry V2 endpoint accepts either 200, or 401 together with a Bearer/Basic authentication challenge and the Registry V2 API header. Generic HTTPS endpoints still require their frozen expected 200 status. TLS, DNS, timeout, connection and unexpected-status failures remain failures.

Sources:

- https://distribution.github.io/distribution/spec/api/#api-version-check
- https://distribution.github.io/distribution/spec/auth/token/
