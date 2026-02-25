# Changelog

All notable changes to AlpenGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-02-25

### Added
- **Testing & Quality Assurance**:
  - Unit tests for KMS module (envelope encryption, DEK caching, rotation)
  - Unit tests for micropayments program (space calculations, account validation)
  - Integration test infrastructure for Oracle endpoints
  - Test placeholders for multi-tenancy, authentication, rate limiting
- **API Documentation**:
  - OpenAPI 3.0 specification (`services/oracle/openapi.yaml`)
  - Complete API reference for all Oracle endpoints
  - Request/response schemas with examples
  - Authentication and security scheme documentation
- **Production Deployment**:
  - Comprehensive production deployment guide (`PRODUCTION_DEPLOYMENT.md`)
  - GCP infrastructure setup (Cloud Run, KMS, Secret Manager)
  - Monitoring and observability setup (Cloud Monitoring, Logging, Tracing)
  - Security hardening procedures (network security, secret rotation, audit logging)
  - Backup and disaster recovery procedures
  - Operational runbook with common operations and incident response
  - Performance optimization guidelines
  - Cost optimization strategies
- **Branch Protection**:
  - Branch protection setup guide (`BRANCH_PROTECTION.md`)
  - Updated `CONTRIBUTING.md` with detailed PR workflow
  - Conventional commit format guidelines
  - Code review and merging procedures

### Changed
- Test infrastructure now supports both unit and integration tests
- Documentation structure improved with dedicated deployment guide

### Documentation
- Added OpenAPI specification for Oracle API
- Added production deployment guide with monitoring setup
- Added branch protection setup instructions
- Enhanced contributing guidelines with PR workflow

## [0.3.0] - 2026-02-25

### Added
- **KMS Envelope Encryption (Phase 3)**:
  - GCP Cloud KMS integration for enterprise-grade key management
  - Per-tenant Data Encryption Keys (DEKs) wrapped by KMS master key
  - DEK caching with configurable TTL (default: 1 hour)
  - Automatic key rotation support via cache invalidation
  - Master key never leaves KMS (zero-knowledge architecture)
  - Fallback to env-provided key for legacy deployments
  - KMS module (`services/oracle/src/kms.rs`) with envelope encryption logic
- **Token-2022 Micropayments (Phase 4)**:
  - New Solana program: `alpenguard-micropayments` with Token-2022 support
  - x402 HTTP 402 Payment Required protocol implementation
  - Payment session creation and execution on-chain
  - USDC (Token-2022) transfers with CpiGuard and ImmutableOwner extensions
  - Automatic refund mechanism for service failures
  - Configurable pricing per trace (lamports)
  - Event emissions for payment tracking (PaymentExecuted, PaymentRefunded)
  - Authority-controlled payment config updates
- **Configuration**:
  - KMS environment variables: `ALPENGUARD_KMS_KEY_NAME`, `ALPENGUARD_KMS_SA_JSON`, `ALPENGUARD_KMS_CACHE_TTL_SECS`
  - Micropayments environment variables: `ALPENGUARD_PAYMENT_ENABLED`, `ALPENGUARD_PAYMENT_PROGRAM_ID`, etc.
  - Updated `.env.example` with comprehensive KMS and micropayments documentation

### Changed
- Oracle `AppState` now includes optional `kms_manager` for envelope encryption
- Anchor workspace updated to include `programs/micropayments`
- Cargo dependencies: added `google-cloudkms1`, `hyper`, `hyper-rustls`, `yup-oauth2` for KMS
- Anchor dependencies: added `spl-token-2022` for micropayments program

### Security
- KMS envelope encryption provides enterprise-grade key management
- Master key never exposed (remains in KMS)
- Per-tenant DEK isolation prevents cross-tenant key reuse
- Token-2022 program uses CpiGuard to prevent unauthorized CPI calls
- Payment verification on-chain before trace delivery

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
