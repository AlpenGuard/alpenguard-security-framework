<div align="center">

# AlpenGuard

![Adobe Express - file (1)](https://github.com/user-attachments/assets/41a6fcc0-674c-41fe-8153-0ce529c72f6c)

**Enterprise-Grade Security & Compliance Middleware for Autonomous AI Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Anchor](https://img.shields.io/badge/anchor-0.30-blueviolet)](https://www.anchor-lang.com/)
[![TypeScript](https://img.shields.io/badge/typescript-5.5-blue)](https://www.typescriptlang.org/)
[![Production Ready](https://img.shields.io/badge/status-production%20ready-brightgreen)](PRODUCTION_DEPLOYMENT.md)

[Features](#-key-features) • [Quick Start](#-quick-start) • [Architecture](#%EF%B8%8F-architecture) • [Security](#-security-model) • [Documentation](#-documentation) • [API Reference](services/oracle/openapi.yaml)

</div>

---

## 🎯 What is AlpenGuard?

AlpenGuard is an **enterprise-grade, zero-trust security framework** for autonomous AI agents operating on Solana. Built for organizations deploying AI agents at scale, AlpenGuard provides comprehensive compliance, security, and monetization infrastructure.

### 🌟 Key Features

#### **Security & Compliance**
- **🔐 Multi-Tenant Isolation**: Complete data segregation with per-tenant encryption keys
- **🔑 KMS Envelope Encryption**: GCP Cloud KMS integration for enterprise key management
- **🛡️ OIDC Authentication**: RS256 JWT validation with scope-based authorization
- **� Compliance Oracle**: OIDC-authenticated trace ingestion with audit logging
- **⛓️ On-Chain Anchoring**: Immutable trace events on Solana blockchain

#### **Blockchain & Payments**
- **� Token-2022 Micropayments**: USDC payments with x402 HTTP 402 protocol
- **💳 Stateless Payments**: Zero-friction payment verification on-chain
- **� Automatic Refunds**: Service failure protection with instant refunds

#### **Developer Experience**
- **📡 RESTful API**: Complete OpenAPI 3.0 specification
- **🎨 Web Console**: Modern React UI for trace exploration
- **� Multi-Backend Storage**: Filesystem, GCS, S3/R2 support
- **⚡ Production Ready**: Comprehensive deployment guides and monitoring

### Why AlpenGuard?

As AI agents gain autonomy, **auditability**, **compliance**, and **monetization** become critical:

#### **Regulatory Compliance**
- **EU AI Act**: Built-in trace-mapping for August 2026 deadline
- **AIUC-1 Standard**: Data protection, zero-trust architecture, 99.99% uptime SLA
- **SOC 2 Ready**: Audit logging, encryption at rest/transit, access controls

#### **Enterprise Security**
- **Zero-Trust Architecture**: Every request authenticated and authorized
- **Defense in Depth**: Multiple security layers (OIDC, KMS, rate limiting, input validation)
- **Tenant Isolation**: Cryptographic separation prevents cross-tenant data leaks

#### **Business Model**
- **Micropayment Infrastructure**: Monetize AI agent services with blockchain payments
- **Pay-Per-Use**: Token-2022 USDC payments with sub-cent precision
- **Instant Settlement**: On-chain payment verification in milliseconds

AlpenGuard bridges the gap between **agent autonomy**, **regulatory compliance**, and **sustainable monetization**.

---

## 🚀 Quick Start

### Prerequisites

- **Rust** 1.75+ (for Compliance Oracle)
- **Node.js** 18+ (for Web Console)
- **Solana CLI** + **Anchor** 0.30+ (for Solana programs)
- **Docker** (optional, for containerized deployment)
- **GCP Account** (optional, for KMS and Cloud Run deployment)

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/AlpenGuard/alpenguard-security-framework.git
cd alpenguard-security-framework
```

### 2️⃣ Configure Environment

Copy `.env.example` and configure:

```bash
cp .env.example .env
```

**Required variables:**

```bash
# Multi-Tenancy: All endpoints require tenant_id
# Tenant ID is validated against OIDC token claim

# Option 1: Simple encryption (development only)
ALPENGUARD_KMS_KEY_B64=<base64-encoded-32-byte-key>

# Option 2: KMS Envelope Encryption (production recommended)
ALPENGUARD_KMS_KEY_NAME=projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
ALPENGUARD_KMS_SA_JSON={"type":"service_account",...}
ALPENGUARD_KMS_CACHE_TTL_SECS=3600

# OIDC Authentication (required for production)
ALPENGUARD_OIDC_ENABLED=1
ALPENGUARD_OIDC_ISSUER=https://your-idp.com
ALPENGUARD_OIDC_AUDIENCE=alpenguard-api
ALPENGUARD_OIDC_JWKS_URL=https://your-idp.com/.well-known/jwks.json

# Micropayments (optional)
ALPENGUARD_PAYMENT_ENABLED=1
ALPENGUARD_PAYMENT_PROGRAM_ID=MPay11111111111111111111111111111111111111
ALPENGUARD_PAYMENT_PRICE_PER_TRACE_LAMPORTS=1000

# For local dev without OIDC (UNSAFE - development only)
ALPENGUARD_ALLOW_INSECURE=1
```

### 3️⃣ Run the Compliance Oracle

```bash
cd services/oracle
cargo run --release
```

Oracle listens on `0.0.0.0:8787` by default.

### 4️⃣ Run the Console (Optional)

```bash
cd apps/console
npm install
npm run dev
```

Open `http://localhost:5173` and configure the Oracle URL.

### 5️⃣ Deploy Solana Programs (Optional)

**AlpenGuard Program** (trace anchoring):
```bash
cd programs/alpenguard
anchor build
anchor deploy --provider.cluster mainnet-beta
```

**Micropayments Program** (Token-2022 payments):
```bash
cd programs/micropayments
anchor build
anchor deploy --provider.cluster mainnet-beta
```

Update `declare_id!` in each `lib.rs` with your program IDs.

### 6️⃣ Production Deployment

For production deployment to Google Cloud Run with monitoring:

```bash
# See comprehensive deployment guide
cat PRODUCTION_DEPLOYMENT.md
```

**Includes:**
- GCP infrastructure setup (Cloud Run, KMS, Secret Manager)
- Monitoring and alerting (Cloud Monitoring, Logging, Tracing)
- Security hardening (network security, secret rotation)
- Backup and disaster recovery (RTO: 1hr, RPO: 15min)
- Operational runbook and incident response

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      AlpenGuard Stack v0.4.0                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐                         ┌──────────────┐      │
│  │   Console    │                         │  Agent SDK   │      │
│  │  (React UI)  │                         │ (TypeScript) │      │
│  │ • Tenant ID  │                         │ • x402 Client│      │
│  └──────┬───────┘                         └──────┬───────┘      │
│         │                                        │               │
│         └────────────────────────────────────────┘               │
│                              │                                   │
│                     ┌────────▼────────┐                          │
│                     │ Compliance      │                          │
│                     │ Oracle (Axum)   │                          │
│                     │ • OIDC Auth     │                          │
│                     │ • Multi-Tenant  │                          │
│                     │ • Rate Limiting │                          │
│                     │ • x402 Protocol │                          │
│                     └────────┬────────┘                          │
│                              │                                   │
│              ┌───────────────┼───────────────┐                   │
│              │               │               │                   │
│       ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐           │
│       │  KMS Envelope│ │     GCS     │ │   S3/R2     │           │
│       │  Encryption  │ │   Storage   │ │  Storage    │           │
│       │ • Per-Tenant │ │ • Encrypted │ │ • Encrypted │           │
│       │   DEKs       │ │   Traces    │ │   Traces    │           │
│       └─────────────┘ └─────────────┘ └─────────────┘           │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Solana Blockchain (Mainnet)                  │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  AlpenGuard Program:                                      │  │
│  │  • TraceRecorded events (immutable audit log)             │  │
│  │  • Kernel config (authority + sequence counter)           │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  Micropayments Program (Token-2022):                      │  │
│  │  • Payment sessions (x402 protocol)                       │  │
│  │  • USDC transfers (CpiGuard + ImmutableOwner)             │  │
│  │  • Automatic refunds                                      │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Technology | Purpose | Status |
|-----------|------------|---------|--------|
| **Compliance Oracle** | Rust (Axum) | Trace ingestion, multi-tenant isolation, KMS encryption | ✅ Production Ready |
| **Web Console** | React + Vite + TypeScript | Trace explorer with tenant ID support | ✅ Production Ready |
| **AlpenGuard Program** | Anchor 0.30 (Rust) | On-chain trace anchoring and events | ✅ Production Ready |
| **Micropayments Program** | Anchor 0.30 + Token-2022 | x402 payment sessions and USDC transfers | ✅ Production Ready |
| **KMS Module** | GCP Cloud KMS | Envelope encryption with per-tenant DEKs | ✅ Production Ready |
| **Storage Backends** | FS / GCS / S3 / R2 | Encrypted trace persistence with tenant isolation | ✅ Production Ready |

### Data Flow

1. **Agent** sends trace to Oracle with `tenant_id` and OIDC token
2. **Oracle** validates OIDC token and `tenant_id` match
3. **Oracle** encrypts payload using KMS-wrapped DEK for tenant
4. **Oracle** stores encrypted trace in GCS/S3 under `traces/{tenant_id}/`
5. **Oracle** optionally anchors hash on Solana blockchain
6. **Console** retrieves and decrypts traces for authorized tenant
7. **Micropayments** (optional) verifies payment before trace delivery

---

## 🔒 Security Model

### Encryption

#### **At Rest (AES-256-GCM)**
- **Algorithm**: AES-256-GCM with 12-byte random nonces
- **Key Management**: 
  - **Legacy**: Env-provided 32-byte key (development only)
  - **Production**: GCP Cloud KMS envelope encryption
- **Envelope Encryption**:
  - Master key never leaves KMS (zero-knowledge)
  - Per-tenant Data Encryption Keys (DEKs)
  - DEKs wrapped by KMS master key
  - DEK caching with 1-hour TTL (configurable)
  - Automatic key rotation support

#### **In Transit**
- **TLS 1.3**: All HTTP traffic encrypted (Cloud Run / reverse proxy)
- **HTTPS Enforcement**: JWKS URLs must use HTTPS (prevents SSRF)

#### **Multi-Tenancy Isolation**
- **Tenant ID Validation**: Request `tenant_id` must match OIDC token claim
- **Storage Isolation**: `{storage_root}/traces/{tenant_id}/`
- **DEK Isolation**: Separate encryption keys per tenant
- **Authorization**: 403 Forbidden on tenant mismatch

### Authentication & Authorization

#### **OIDC (OpenID Connect)**
- **Algorithm**: RS256 JWT validation
- **JWKS Caching**: 5-minute TTL (configurable)
- **Required Claims**:
  - `sub`: Subject (user/agent ID)
  - `iss`: Issuer (must match configured issuer)
  - `aud`: Audience (must match configured audience)
  - `exp`: Expiration timestamp
  - `scope`: Space-separated scopes
  - `tenant_id`: Tenant identifier (for multi-tenancy)

#### **Scopes**
- `traces:ingest`: Permission to ingest traces
- `traces:read`: Permission to read traces
- `admin:rotate`: Permission to rotate DEKs (future)

#### **Security Features**
- **Audience Type Validation**: Prevents type confusion attacks (GHSA-h395-gr6q-cpjc)
- **HTTPS JWKS**: Enforces HTTPS for JWKS URLs (prevents SSRF)
- **Secure-by-Default**: Requires explicit `ALPENGUARD_ALLOW_INSECURE=1` when OIDC disabled
- **Token Expiry**: Validates `exp` claim to prevent replay attacks

### Input Validation

- Request body limits: 262KB (configurable)
- Trace payload limits: 128KB (configurable)
- SHA-256 hash verification on ingest
- ID sanitization (alphanumeric + `-_` only)

### Rate Limiting

- Tower-governor middleware
- Configurable RPS (default: 25)
- HTTP timeouts: 10s request, 5s connect

### Audit Logging

- Structured logs for all operations
- Subject tracking (OIDC `sub` or `agent_id`)
- Action-based events (`traces.ingest`, `traces.read`)

---

## 📚 Documentation

### **Core Documentation**

| Document | Description |
|----------|-------------|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | System design and component interactions |
| [`PRODUCTION_DEPLOYMENT.md`](PRODUCTION_DEPLOYMENT.md) | **Production deployment guide** (GCP, monitoring, security) |
| [`services/oracle/openapi.yaml`](services/oracle/openapi.yaml) | **OpenAPI 3.0 specification** for Oracle API |
| [`ROADMAP.md`](ROADMAP.md) | 12-week implementation plan and milestones |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history and release notes |

### **Deployment Guides**

| Document | Description |
|----------|-------------|
| [`DEPLOY_CLOUD_RUN.md`](DEPLOY_CLOUD_RUN.md) | Google Cloud Run deployment (legacy) |
| [`DEPLOY_R2.md`](DEPLOY_R2.md) | Cloudflare R2 storage configuration |
| [`PRODUCTION_DEPLOYMENT.md`](PRODUCTION_DEPLOYMENT.md) | **Comprehensive production guide** (recommended) |

### **Development & Contribution**

| Document | Description |
|----------|-------------|
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution guidelines and PR workflow |
| [`BRANCH_PROTECTION.md`](BRANCH_PROTECTION.md) | Branch protection setup for maintainers |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting policy |

### **API Reference**

- **OpenAPI Specification**: [`services/oracle/openapi.yaml`](services/oracle/openapi.yaml)
- **Endpoints**:
  - `GET /healthz` - Health check
  - `POST /v1/traces:ingest` - Ingest encrypted trace
  - `GET /v1/traces:list` - List traces for tenant
  - `POST /v1/traces:get` - Get and decrypt specific trace

---

## 🗺️ Roadmap

### ✅ Phase 1: Multi-Tenancy (v0.2.0 - Complete)

- ✅ Tenant isolation at all levels (storage, authorization, encryption)
- ✅ `tenant_id` validation against OIDC token claims
- ✅ Tenant-scoped storage paths
- ✅ Audit logging for tenant mismatch attempts

### ✅ Phase 2: CI/CD Pipeline (v0.2.0 - Complete)

- ✅ GitHub Actions workflows (Oracle tests, Console build)
- ✅ Dependabot for automated dependency updates
- ✅ Security audit integration (`cargo audit`)
- ✅ Branch protection and PR workflow

### ✅ Phase 3: KMS Envelope Encryption (v0.3.0 - Complete)

- ✅ GCP Cloud KMS integration
- ✅ Per-tenant Data Encryption Keys (DEKs)
- ✅ DEK caching with configurable TTL
- ✅ Automatic key rotation support
- ✅ Master key never leaves KMS (zero-knowledge)

### ✅ Phase 4: Token-2022 Micropayments (v0.3.0 - Complete)

- ✅ x402 HTTP 402 Payment Required protocol
- ✅ Solana program with Token-2022 support
- ✅ Payment session creation and execution
- ✅ USDC transfers with proper decimal handling
- ✅ Automatic refund mechanism

### ✅ Production Readiness (v0.4.0 - Complete)

- ✅ Comprehensive testing infrastructure
- ✅ OpenAPI 3.0 specification
- ✅ Production deployment guide
- ✅ Monitoring and observability setup
- ✅ Security hardening procedures
- ✅ Backup and disaster recovery

### 🔮 Phase 5: Red-Teaming Engine (Planned)

- Adversarial agent sandbox with isolation
- Behavioral pattern detection and analysis
- Chaos engineering test templates
- Automated red-teaming runs
- Results timeline and reporting

### 🔮 Future Enhancements (Planned)

- Trace export bundles with on-chain attestation
- OpenTelemetry collector integration
- MFA enforcement for admin operations
- EU AI Act compliance certification
- Subject-based rate limiting

See [`ROADMAP.md`](ROADMAP.md) for detailed milestones and timelines.

---

## 🤝 Contributing

We welcome contributions! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) for detailed guidelines.

### Development Workflow

1. **Fork and clone** the repository
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Make changes** and add tests
4. **Run tests**: `cargo test` (Oracle), `npm test` (Console)
5. **Format code**: `cargo fmt`, `cargo clippy`
6. **Commit**: Use conventional commits (`feat:`, `fix:`, `docs:`)
7. **Push and create PR** on GitHub

### Development Setup

```bash
# Clone repository
git clone https://github.com/AlpenGuard/alpenguard-security-framework.git
cd alpenguard-security-framework

# Install Oracle dependencies
cd services/oracle
cargo build

# Install Console dependencies
cd apps/console
npm install

# Run tests
cd services/oracle
cargo test

cd programs/micropayments
cargo test

cd apps/console
npm test

# Format code
cargo fmt
cargo clippy
npm run format
```

### Pull Request Guidelines

- **Status Checks**: All CI/CD checks must pass
- **Code Review**: At least 1 approval required
- **Conventional Commits**: Use semantic commit messages
- **Tests**: Add tests for new features and bug fixes
- **Documentation**: Update relevant docs

### Security

Found a vulnerability? **Do not open a public issue.** Please report it privately via our [Security Policy](SECURITY.md).

---

## 📄 License

MIT License - see [`LICENSE`](LICENSE) for details.

---

## 🙏 Acknowledgments

- **Solana Foundation** for blockchain infrastructure and ecosystem support
- **Anchor Framework** for Solana program development and Token-2022 integration
- **Axum** for high-performance, production-ready HTTP server
- **Google Cloud Platform** for KMS, Cloud Run, and enterprise infrastructure
- **jsonwebtoken** for secure OIDC validation and JWT handling
- **Tower** ecosystem for middleware (rate limiting, CORS, tracing)
- **React** and **Vite** for modern, performant web console

---

<div align="center">

**Built with ❤️ for the autonomous agent ecosystem**

**Production Ready** • **Enterprise Grade** • **Open Source**

[GitHub](https://github.com/AlpenGuard/alpenguard-security-framework) • [API Docs](services/oracle/openapi.yaml) • [Deployment Guide](PRODUCTION_DEPLOYMENT.md) • [Report Issue](https://github.com/AlpenGuard/alpenguard-security-framework/issues)

---

### 📊 Project Status

- **Version**: v0.4.0 (Production Ready)
- **License**: MIT
- **Status**: ✅ Production Ready
- **Deployment**: GCP Cloud Run, Solana Mainnet
- **Estimated Cost**: $90-190/month (1000 tenants, 1M traces)

### 🚀 Quick Links

- [Production Deployment Guide](PRODUCTION_DEPLOYMENT.md)
- [OpenAPI Specification](services/oracle/openapi.yaml)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

</div>
