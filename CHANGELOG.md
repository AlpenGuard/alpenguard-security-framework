# Changelog

All notable changes to AlpenGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-25

### Added
- **Multi-Tenancy (Phase 1)**:
  - `tenant_id` field added to all trace structures (Claims, TraceIngestRequest, TraceSummary, TraceGetRequest)
  - Tenant-scoped authorization: validates request `tenant_id` matches OIDC claim `tenant_id`
  - Tenant-isolated storage paths: `{storage_root}/traces/{tenant_id}/` for FS/GCS/S3
  - Tenant filtering in list endpoint (only shows authorized tenant's traces)
  - Audit logging for tenant mismatch attempts
- **CI/CD Pipeline (Phase 2)**:
  - GitHub Actions workflow for Oracle tests (cargo test, clippy, fmt, security audit)
  - GitHub Actions workflow for Console build (npm build, type-check)
  - Dependabot configuration for automated dependency updates (Cargo, npm, GitHub Actions)
  - Weekly dependency update schedule with auto-labeling
- **Console Updates**:
  - Tenant ID input field with localStorage persistence
  - Updated TraceSummary type to include `tenant_id`
  - Tenant ID included in trace detail display
  - Multi-tenancy documentation in UI

### Changed
- **BREAKING**: All trace API endpoints now require `tenant_id` field
- Console API calls updated to include `tenant_id` in requests
- `.env.example` updated with multi-tenancy documentation
- Storage backend functions updated to accept `tenant_id` parameter

### Removed
- **VS Code Extension**: Removed entire extension codebase and references
  - Deleted `apps/vscode-extension/` directory (7 files, 1,042 lines)
  - Removed extension references from README.md, CHANGELOG.md, .gitignore
  - Focus shifted to web console only for trace exploration

### Security
- JWKS URL validation: enforces HTTPS to prevent SSRF attacks
- Tenant isolation prevents cross-tenant data leaks
- Storage path sanitization prevents directory traversal

## [0.1.0] - 2026-02-25

### Added
- **Compliance Oracle (Rust/Axum)**:
  - OIDC authentication with RS256 JWT validation
  - AES-256-GCM encryption at rest for trace payloads
  - Multi-backend storage: filesystem, GCS, S3-compatible (Cloudflare R2)
  - Rate limiting with configurable RPS
  - CORS configuration for console origins
  - Audit logging for all trace operations
  - Secure-by-default: requires explicit `ALPENGUARD_ALLOW_INSECURE=1` when OIDC disabled
- **Console (React/Vite)**:
  - Trace Explorer UI with list/get/ping operations
  - Opt-in bearer token persistence
  - Security headers and CSP in nginx config
- **Solana Program (Anchor)**:
  - On-chain trace anchoring via `TraceRecorded` events
  - Kernel initialization with authority validation
  - Trace sequence counter with overflow protection
- **Documentation**:
  - Architecture overview (`ARCHITECTURE.md`)
  - 12-week implementation roadmap (`ROADMAP.md`)
  - Cloud Run deployment guide (`DEPLOY_CLOUD_RUN.md`)
  - Cloudflare R2 storage guide (`DEPLOY_R2.md`)
  - Security policy (`SECURITY.md`)
  - Contributing guidelines (`CONTRIBUTING.md`)

### Security
- Upgraded `jsonwebtoken` from 9.3.0 to 10.2.0 (fixes GHSA-h395-gr6q-cpjc type confusion vulnerability)
- Added explicit audience type validation to prevent JWT `aud` claim type confusion
- Upgraded Vite toolchain to pull `esbuild` 0.25.12 (fixes GHSA-67mh-4wv8-2f99 dev server CORS vulnerability)
- Request body size limits (262KB default, configurable)
- Trace payload size limits (128KB default, configurable)
- HTTP client timeouts (10s request, 5s connect)
- Input sanitization for trace IDs and span IDs
- SHA-256 payload hash verification on ingest
- Nonce validation (12 bytes) for AES-GCM decryption

### Changed
- Console bearer token storage is now opt-in (default: non-persistent)
- Oracle requires encryption key (`ALPENGUARD_KMS_KEY_B64`) for trace ingestion
- JWKS caching with configurable TTL (300s default)
- GCP access token caching with automatic refresh

## [Unreleased]

### Planned
- KMS envelope encryption with per-tenant DEKs (Phase 3)
- Token-2022 micropayment integration (x402 protocol)
- Red-teaming engine with behavioral analysis
- Trace export bundles with on-chain attestation
- OpenTelemetry collector integration
- MFA enforcement for admin operations
- Subject-based rate limiting (when OIDC enabled)
