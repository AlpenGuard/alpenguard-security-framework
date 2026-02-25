# Deploy AlpenGuard (Cloud Run)

This guide deploys the **Oracle API** and the **Operator Console** to GCP Cloud Run.

## Prereqs

- `gcloud` installed and authenticated
- A GCP project selected

## 1) Set environment

```bash
gcloud config set project <YOUR_GCP_PROJECT_ID>
export REGION=us-central1
```

## 2) Build and deploy Oracle API

### Build

```bash
gcloud builds submit --tag gcr.io/<YOUR_GCP_PROJECT_ID>/alpenguard-oracle:devnet-beta ./services/oracle
```

### Deploy

Cloud Run will set `PORT=8080` automatically; the service binds to `0.0.0.0:$PORT`.

```bash
gcloud run deploy alpenguard-oracle \
  --image gcr.io/<YOUR_GCP_PROJECT_ID>/alpenguard-oracle:devnet-beta \
  --region $REGION \
  --no-allow-unauthenticated
```

### Grant invoker access (IAM)

By default, a Cloud Run service with `--no-allow-unauthenticated` requires an authenticated caller with the **Run Invoker** role.

Grant one or more Google identities access:

```bash
gcloud run services add-iam-policy-binding alpenguard-oracle \
  --region $REGION \
  --member="user:<YOUR_EMAIL>" \
  --role="roles/run.invoker"
```

For a service account (recommended for automation):

```bash
gcloud run services add-iam-policy-binding alpenguard-oracle \
  --region $REGION \
  --member="serviceAccount:<YOUR_SA_NAME>@<YOUR_GCP_PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/run.invoker"
```

#### Required env vars (minimum)

Set these either through the Cloud Run UI, `--set-env-vars`, or (recommended) Secret Manager.

- `ALPENGUARD_KMS_KEY_B64` (base64, **32 bytes decoded**)
- `ALPENGUARD_OIDC_ENABLED=0`
- `ALPENGUARD_ALLOW_INSECURE=1` (required when OIDC is disabled; rely on Cloud Run IAM / edge auth)
- `ALPENGUARD_CORS_ORIGINS=https://<YOUR_CONSOLE_DOMAIN>`

Durable storage (recommended):
- `ALPENGUARD_GCS_BUCKET=<YOUR_BUCKET_NAME>`
- `ALPENGUARD_GCS_PREFIX=alpenguard` (optional)

Optional:
- `ALPENGUARD_RATELIMIT_RPS` (default `25`)
- `ALPENGUARD_OIDC_JWKS_TTL_SECS` (only relevant if OIDC is enabled)

### Durable storage (GCS) setup

The Oracle can store encrypted trace records in Google Cloud Storage.

1. Create a bucket:

```bash
gsutil mb -l $REGION gs://<YOUR_BUCKET_NAME>
```

2. Grant the Cloud Run runtime service account object access.

First, identify the service account used by the `alpenguard-oracle` service.

If you did not set one explicitly, Cloud Run commonly uses the Compute default service account:
`<YOUR_GCP_PROJECT_NUMBER>-compute@developer.gserviceaccount.com`

Then grant object permissions:

```bash
gsutil iam ch \
  serviceAccount:<YOUR_SA_EMAIL>:objectAdmin \
  gs://<YOUR_BUCKET_NAME>
```

3. Set env vars on the Cloud Run service:

```bash
gcloud run services update alpenguard-oracle \
  --region $REGION \
  --set-env-vars ALPENGUARD_GCS_BUCKET=<YOUR_BUCKET_NAME>,ALPENGUARD_GCS_PREFIX=alpenguard
```

## 3) Build and deploy Operator Console

### Build

```bash
gcloud builds submit --tag gcr.io/<YOUR_GCP_PROJECT_ID>/alpenguard-console:devnet-beta ./apps/console
```

### Deploy

```bash
gcloud run deploy alpenguard-console \
  --image gcr.io/<YOUR_GCP_PROJECT_ID>/alpenguard-console:devnet-beta \
  --region $REGION \
  --allow-unauthenticated
```

## 4) Wire Console to Oracle

The console currently lets operators set the Oracle URL inside the UI.

Recommended production setup:
- Use a custom domain for both services
- Set `ALPENGUARD_CORS_ORIGINS` on the Oracle to the Console origin

### Calling a private Oracle from the Console

When the Oracle is IAM-protected, browser requests must include an **identity token**.

You can generate one and paste it into the Console **Trace Explorer → Bearer token** field:

1. Get the Oracle URL:

```bash
ORACLE_URL=$(gcloud run services describe alpenguard-oracle --region $REGION --format='value(status.url)')
echo $ORACLE_URL
```

2. Mint an identity token with the Oracle URL as audience:

```bash
gcloud auth print-identity-token --audiences=$ORACLE_URL
```

Paste that token in the Console and use **List traces** / **Get trace**.

## 5) Validate

- Console loads
- Oracle responds to:
  - `GET /healthz`
- With an access token:
  - `GET /v1/traces:list`
  - `POST /v1/traces:get`

For IAM mode, the “access token” above is a **Google identity token**.

## Notes (Cloud Run storage)

Cloud Run filesystem is ephemeral. The Oracle currently stores encrypted traces in `ALPENGUARD_DATA_DIR` (default `/tmp/alpenguard-data`).

For a true public beta, the next step is moving trace persistence to a managed store (e.g. Cloud SQL / Firestore / GCS) while keeping encryption-at-rest.
