# Deploy durable trace storage with Cloudflare R2 (S3-compatible)

This guide configures the AlpenGuard **Oracle** to store encrypted trace records durably in **Cloudflare R2**.

## What this enables

- Trace payloads remain **encrypted at rest** by the Oracle (AES-256-GCM) using `ALPENGUARD_KMS_KEY_B64`.
- The Oracle persists encrypted `TraceRecord` JSON objects to R2 using an **S3-compatible** API.
- The Console Trace Explorer can list/get traces via the Oracle as usual.

## 1) Create an R2 bucket

In Cloudflare Dashboard:

- Go to **R2**
- Create a bucket, e.g. `alpenguard-traces-devnet`

You will use this bucket name as:

- `ALPENGUARD_S3_BUCKET=alpenguard-traces-devnet`

## 2) Create R2 API tokens / access keys

In Cloudflare Dashboard:

- Go to **R2 → Manage R2 API Tokens**
- Create an API token with permissions for the bucket:
  - Read objects
  - Write objects
  - List objects

Copy these values:

- **Access Key ID**
- **Secret Access Key**
- **Account ID**

## 3) Set Oracle environment variables

### Required encryption key

`ALPENGUARD_KMS_KEY_B64` must be base64 that decodes to **exactly 32 bytes**.

### R2 (S3) settings

Set:

- `ALPENGUARD_S3_BUCKET=<YOUR_BUCKET_NAME>`
- `ALPENGUARD_S3_PREFIX=alpenguard` (optional)
- `ALPENGUARD_S3_REGION=auto`
- `ALPENGUARD_S3_ENDPOINT=https://<ACCOUNT_ID>.r2.cloudflarestorage.com`
- `ALPENGUARD_S3_ACCESS_KEY_ID=<YOUR_ACCESS_KEY_ID>`
- `ALPENGUARD_S3_SECRET_ACCESS_KEY=<YOUR_SECRET_ACCESS_KEY>`

Notes:

- The Oracle will prefer S3 storage when `ALPENGUARD_S3_BUCKET` is set.
- Do **not** commit credentials. Use your hosting provider’s secret manager.

## 4) Validate

1. Restart/redeploy the oracle with the env vars set.
2. In logs, you should see:

- `S3-compatible storage enabled`

3. In the Console:

- Open **Trace Explorer**
- List traces
- Fetch a trace payload

4. In Cloudflare R2 bucket, you should see objects under:

- `<prefix>/traces/...`

## Troubleshooting

- If you see an error about missing variables:
  - Ensure `ALPENGUARD_S3_ENDPOINT`, `ALPENGUARD_S3_ACCESS_KEY_ID`, and `ALPENGUARD_S3_SECRET_ACCESS_KEY` are set.
- If list/get works locally but not in deploy:
  - Ensure outbound HTTPS to `*.r2.cloudflarestorage.com` is allowed.
- If decrypt fails:
  - Verify the same `ALPENGUARD_KMS_KEY_B64` is configured for the oracle instance that wrote the trace.
