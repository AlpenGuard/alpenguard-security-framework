<div align="center">

# AlpenGuard

![Adobe Express - file (1)](https://github.com/user-attachments/assets/41a6fcc0-674c-41fe-8153-0ce529c72f6c)

**Security & Compliance Middleware for Autonomous AI Agents on Solana**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Anchor](https://img.shields.io/badge/anchor-0.30-blueviolet)](https://www.anchor-lang.com/)
[![TypeScript](https://img.shields.io/badge/typescript-5.5-blue)](https://www.typescriptlang.org/)

[Documentation](#documentation) • [Quick Start](#quick-start) • [Architecture](#architecture) • [Security](#security-model) • [VS Code Extension](#vs-code-extension)

</div>

---

## 🎯 What is AlpenGuard?

AlpenGuard is a **zero-trust security framework** for autonomous AI agents operating on Solana. It provides:

- **🔐 Compliance Oracle**: OIDC-authenticated trace ingestion with AES-256-GCM encryption at rest
- **⛓️ On-Chain Anchoring**: Immutable trace events on Solana via Anchor program
- **🛡️ Red-Teaming Engine**: Behavioral analysis and adversarial testing (roadmap)
- **💰 Micropayment Gateway**: Token-2022 integration with x402 protocol (roadmap)
- **📊 Trace Explorer**: Web console + VS Code extension for compliance auditing

### Why AlpenGuard?

As AI agents gain autonomy, **auditability** and **compliance** become critical:

- **EU AI Act**: Trace-mapping requirements (August 2026 deadline)
- **AIUC-1 Standard**: Data protection, zero-trust, 99.99% uptime
- **Enterprise Security**: MFA, encryption at rest/transit, scope-based authorization

AlpenGuard bridges the gap between **agent autonomy** and **regulatory compliance**.

---

## 🚀 Quick Start

### Prerequisites

- **Rust** 1.75+ (for Oracle)
- **Node.js** 18+ (for Console/Extension)
- **Solana CLI** + **Anchor** 0.30+ (for on-chain program)

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
# Encryption key (base64, decodes to 32 bytes)
ALPENGUARD_KMS_KEY_B64=<your-base64-key>

# OIDC (recommended for production)
ALPENGUARD_OIDC_ENABLED=1
ALPENGUARD_OIDC_ISSUER=https://your-idp.com
ALPENGUARD_OIDC_AUDIENCE=alpenguard-api
ALPENGUARD_OIDC_JWKS_URL=https://your-idp.com/.well-known/jwks.json

# For local dev without OIDC (unsafe for production)
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

### 5️⃣ Deploy the Solana Program (Optional)

```bash
cd programs/alpenguard
anchor build
anchor deploy
```

Update `declare_id!` in `lib.rs` with your program ID.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AlpenGuard Stack                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Console    │  │  VS Code Ext │  │  Agent SDK   │     │
│  │  (React UI)  │  │  (TypeScript)│  │ (TypeScript) │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                 │                 │              │
│         └─────────────────┼─────────────────┘              │
│                           │                                │
│                  ┌────────▼────────┐                       │
│                  │ Compliance      │                       │
│                  │ Oracle (Axum)   │                       │
│                  │ • OIDC Auth     │                       │
│                  │ • AES-256-GCM   │                       │
│                  │ • Rate Limiting │                       │
│                  └────────┬────────┘                       │
│                           │                                │
│         ┌─────────────────┼─────────────────┐             │
│         │                 │                 │             │
│  ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐    │
│  │  Filesystem │   │     GCS     │   │ S3/R2 (AWS) │    │
│  │   Storage   │   │   Storage   │   │   Storage   │    │
│  └─────────────┘   └─────────────┘   └─────────────┘    │
│                                                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │          Solana Blockchain (Anchor)                │  │
│  │  • TraceRecorded events (immutable audit log)      │  │
│  │  • Kernel config (authority + sequence counter)    │  │
│  └────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
```

### Components

| Component | Technology | Purpose |
|-----------|------------|----------|
| **Compliance Oracle** | Rust (Axum) | Trace ingestion, encryption, storage |
| **Console** | React + Vite | Web-based trace explorer |
| **VS Code Extension** | TypeScript | IDE-native trace explorer |
| **Solana Program** | Anchor (Rust) | On-chain trace anchoring |
| **Storage Backends** | FS / GCS / S3 | Encrypted trace persistence |

---

## 🔒 Security Model

### Encryption

- **At Rest**: AES-256-GCM with 12-byte nonces
- **In Transit**: TLS 1.3 (terminate at reverse proxy / Cloud Run)
- **Key Management**: Env-provided key (Phase 1) → KMS envelope encryption (roadmap)

### Authentication & Authorization

- **OIDC**: RS256 JWT validation with JWKS caching
- **Scopes**: `traces:ingest`, `traces:read`
- **Audience Validation**: Explicit type checking (prevents type confusion attacks)
- **Secure-by-Default**: Requires `ALPENGUARD_ALLOW_INSECURE=1` when OIDC disabled

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

## 💻 VS Code Extension

Install the AlpenGuard extension from the VS Code Marketplace:

```
code --install-extension AlpenGuard.alpenguard
```

### Features

- **Trace Explorer**: List/get traces directly in VS Code
- **Secure Token Storage**: Uses VS Code SecretStorage (OS keychain)
- **Configurable Oracle URL**: Workspace-scoped settings
- **Strict CSP**: Nonce-based script execution, no inline scripts

### Commands

- `AlpenGuard: Open Trace Explorer`
- `AlpenGuard: Set Bearer Token`
- `AlpenGuard: Clear Bearer Token`
- `AlpenGuard: Ping Oracle`

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | System design and component interactions |
| [`ROADMAP.md`](ROADMAP.md) | 12-week implementation plan |
| [`DEPLOY_CLOUD_RUN.md`](DEPLOY_CLOUD_RUN.md) | Google Cloud Run deployment guide |
| [`DEPLOY_R2.md`](DEPLOY_R2.md) | Cloudflare R2 storage configuration |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting policy |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution guidelines |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history and release notes |

---

## 🗺️ Roadmap

### ✅ Phase 1 (Complete)

- On-chain trace anchoring (Solana/Anchor)
- Compliance Oracle with OIDC auth
- AES-256-GCM encryption at rest
- Web console + VS Code extension
- Multi-backend storage (FS/GCS/S3)

### 🚧 Phase 2 (In Progress)

- Multi-tenancy support
- KMS envelope encryption
- Token-2022 micropayments (x402 protocol)
- Red-teaming engine with behavioral analysis

### 🔮 Phase 3 (Planned)

- Trace export bundles with attestation
- OpenTelemetry collector integration
- MFA enforcement for admin operations
- EU AI Act compliance certification

See [`ROADMAP.md`](ROADMAP.md) for detailed milestones.

---

## 🤝 Contributing

We welcome contributions! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Install dependencies
npm install
cargo build

# Run tests (when available)
cargo test
npm test

# Format code
cargo fmt
npm run format
```

### Security

Found a vulnerability? Please report it privately via our [Security Policy](SECURITY.md).

---

## 📄 License

MIT License - see [`LICENSE`](LICENSE) for details.

---

## 🙏 Acknowledgments

- **Solana Foundation** for blockchain infrastructure
- **Anchor Framework** for Solana program development
- **Axum** for high-performance HTTP server
- **jsonwebtoken** for OIDC validation

---

<div align="center">

**Built with ❤️ for the autonomous agent ecosystem**

[GitHub](https://github.com/AlpenGuard/alpenguard-security-framework) • [Documentation](ARCHITECTURE.md) • [Report Issue](https://github.com/AlpenGuard/alpenguard-security-framework/issues)

</div>
