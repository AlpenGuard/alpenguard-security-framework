# AlpenGuard

Security and red-teaming middleware for autonomous AI agents on Solana.

This repository is a monorepo containing:

- `apps/console`: operator console (React + Vite)
- `services/oracle`: Compliance Oracle HTTP API (Axum)
- `programs/alpenguard`: Solana program (Anchor)

## Status

This is an **early / Phase 1** foundation:

- On-chain: trace anchoring via emitted events (`TraceRecorded`).
- Off-chain: encrypted trace payload storage in the Oracle (AES-256-GCM).
- Console: Trace Explorer can ping/list/get traces from the Oracle.

## Quick start (dev)

### 1) Configure environment

Copy the example env file and fill in values (never commit real secrets):

- Use `.env.example` as a template.
- The Oracle requires `ALPENGUARD_KMS_KEY_B64` (base64 that decodes to **32 bytes**).

If you are running locally without OIDC, the Oracle requires explicit acknowledgement:

- `ALPENGUARD_ALLOW_INSECURE=1`

### 2) Run the Oracle

From `services/oracle`:

- Build/run with Cargo (see `services/oracle/Cargo.toml`)

The Oracle listens on:

- `0.0.0.0:8787` by default

### 3) Run the Console

From `apps/console`:

- `npm run dev`

Open the console and set the Oracle URL in the sidebar.

## Security model (high level)

- Encryption at rest: trace payloads are stored encrypted by the Oracle using AES-256-GCM.
- Encryption in transit: terminate TLS in your reverse proxy / hosting layer.
- AuthN/Z (recommended for any public deployment): enable OIDC and require scopes:
  - `traces:ingest`
  - `traces:read`

## Repository hygiene

- Never commit secrets. `.gitignore` excludes `.env*`, key material, and common local data dirs.
- Use your cloud provider secret manager for all credentials.

## Docs

- `ARCHITECTURE.md`: system overview
- `ROADMAP.md`: implementation roadmap
- `DEPLOY_CLOUD_RUN.md`: deploy to Cloud Run
- `DEPLOY_R2.md`: configure Cloudflare R2 (S3-compatible) durable storage

## License

MIT. See `LICENSE`.
