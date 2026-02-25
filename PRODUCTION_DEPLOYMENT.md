# Production Deployment Guide

This guide covers deploying AlpenGuard to production with monitoring, observability, and operational best practices.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Infrastructure Setup](#infrastructure-setup)
3. [Oracle Deployment](#oracle-deployment)
4. [Console Deployment](#console-deployment)
5. [Solana Programs](#solana-programs)
6. [Monitoring & Observability](#monitoring--observability)
7. [Security Hardening](#security-hardening)
8. [Backup & Disaster Recovery](#backup--disaster-recovery)
9. [Operational Runbook](#operational-runbook)

---

## Prerequisites

### Required Services

- **Google Cloud Platform** (for Cloud Run, KMS, GCS)
- **Cloudflare** (for R2 storage, optional)
- **OIDC Provider** (Auth0, Okta, Google, etc.)
- **Solana RPC** (QuickNode, Helius, or self-hosted)

### Required Tools

```bash
# Google Cloud SDK
gcloud --version

# Docker
docker --version

# Solana CLI
solana --version

# Anchor CLI
anchor --version

# Node.js & npm
node --version
npm --version
```

---

## Infrastructure Setup

### 1. GCP Project Setup

```bash
# Set project
export PROJECT_ID="alpenguard-prod"
gcloud config set project $PROJECT_ID

# Enable required APIs
gcloud services enable \
  run.googleapis.com \
  cloudkms.googleapis.com \
  storage-api.googleapis.com \
  secretmanager.googleapis.com \
  monitoring.googleapis.com \
  logging.googleapis.com
```

### 2. Create KMS Key Ring and Key

```bash
# Create key ring
gcloud kms keyrings create alpenguard \
  --location=us-central1

# Create encryption key
gcloud kms keys create oracle-master-key \
  --location=us-central1 \
  --keyring=alpenguard \
  --purpose=encryption

# Get key name (save this)
export KMS_KEY_NAME="projects/$PROJECT_ID/locations/us-central1/keyRings/alpenguard/cryptoKeys/oracle-master-key"
echo $KMS_KEY_NAME
```

### 3. Create Service Account for Oracle

```bash
# Create service account
gcloud iam service-accounts create alpenguard-oracle \
  --display-name="AlpenGuard Oracle Service Account"

# Grant KMS permissions
gcloud kms keys add-iam-policy-binding oracle-master-key \
  --location=us-central1 \
  --keyring=alpenguard \
  --member="serviceAccount:alpenguard-oracle@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"

# Grant Cloud Run permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:alpenguard-oracle@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/run.invoker"

# Create and download key
gcloud iam service-accounts keys create oracle-sa-key.json \
  --iam-account=alpenguard-oracle@$PROJECT_ID.iam.gserviceaccount.com

# Save key to Secret Manager
gcloud secrets create alpenguard-kms-sa-json \
  --data-file=oracle-sa-key.json

# Clean up local key file
rm oracle-sa-key.json
```

### 4. Create Secrets

```bash
# Generate encryption key (fallback, not needed if using KMS)
openssl rand -base64 32 | gcloud secrets create alpenguard-kms-key-b64 --data-file=-

# OIDC configuration
echo "https://your-oidc-provider.com" | gcloud secrets create alpenguard-oidc-issuer --data-file=-
echo "alpenguard-api" | gcloud secrets create alpenguard-oidc-audience --data-file=-
echo "https://your-oidc-provider.com/.well-known/jwks.json" | gcloud secrets create alpenguard-oidc-jwks-url --data-file=-
```

---

## Oracle Deployment

### 1. Build Docker Image

```bash
cd services/oracle

# Build image
docker build -t gcr.io/$PROJECT_ID/alpenguard-oracle:latest .

# Push to GCR
docker push gcr.io/$PROJECT_ID/alpenguard-oracle:latest
```

### 2. Deploy to Cloud Run

```bash
gcloud run deploy alpenguard-oracle \
  --image=gcr.io/$PROJECT_ID/alpenguard-oracle:latest \
  --platform=managed \
  --region=us-central1 \
  --service-account=alpenguard-oracle@$PROJECT_ID.iam.gserviceaccount.com \
  --allow-unauthenticated \
  --min-instances=1 \
  --max-instances=10 \
  --cpu=2 \
  --memory=1Gi \
  --timeout=60s \
  --concurrency=80 \
  --set-env-vars="ALPENGUARD_OIDC_ENABLED=1" \
  --set-secrets="ALPENGUARD_KMS_KEY_B64=alpenguard-kms-key-b64:latest,ALPENGUARD_OIDC_ISSUER=alpenguard-oidc-issuer:latest,ALPENGUARD_OIDC_AUDIENCE=alpenguard-oidc-audience:latest,ALPENGUARD_OIDC_JWKS_URL=alpenguard-oidc-jwks-url:latest,ALPENGUARD_KMS_SA_JSON=alpenguard-kms-sa-json:latest" \
  --set-env-vars="ALPENGUARD_KMS_KEY_NAME=$KMS_KEY_NAME,ALPENGUARD_RATELIMIT_RPS=100,ALPENGUARD_CORS_ORIGINS=https://console.alpenguard.io"
```

### 3. Configure Custom Domain (Optional)

```bash
# Map custom domain
gcloud run domain-mappings create \
  --service=alpenguard-oracle \
  --domain=oracle.alpenguard.io \
  --region=us-central1

# Update DNS records as instructed by GCP
```

---

## Console Deployment

### 1. Build Console

```bash
cd apps/console

# Install dependencies
npm ci

# Build production bundle
npm run build
```

### 2. Deploy to Cloud Storage + CDN

```bash
# Create bucket
gsutil mb -l us-central1 gs://alpenguard-console

# Enable website configuration
gsutil web set -m index.html -e index.html gs://alpenguard-console

# Upload build
gsutil -m rsync -r -d dist/ gs://alpenguard-console

# Make public
gsutil iam ch allUsers:objectViewer gs://alpenguard-console

# Set up Cloud CDN (via Load Balancer)
# Follow: https://cloud.google.com/cdn/docs/setting-up-cdn-with-bucket
```

### 3. Alternative: Deploy to Netlify/Vercel

```bash
# Netlify
netlify deploy --prod --dir=dist

# Vercel
vercel --prod
```

---

## Solana Programs

### 1. Deploy AlpenGuard Program

```bash
cd programs/alpenguard

# Build program
anchor build

# Deploy to mainnet-beta
anchor deploy --provider.cluster mainnet-beta

# Initialize kernel (replace with your authority pubkey)
anchor run initialize --provider.cluster mainnet-beta
```

### 2. Deploy Micropayments Program

```bash
cd programs/micropayments

# Build program
anchor build

# Deploy to mainnet-beta
anchor deploy --provider.cluster mainnet-beta

# Initialize payment config
# (Use Anchor client or custom script)
```

---

## Monitoring & Observability

### 1. Cloud Monitoring Setup

```bash
# Create uptime check
gcloud monitoring uptime create alpenguard-oracle-health \
  --resource-type=uptime-url \
  --host=oracle.alpenguard.io \
  --path=/healthz \
  --check-interval=60s

# Create alert policy
gcloud alpha monitoring policies create \
  --notification-channels=CHANNEL_ID \
  --display-name="AlpenGuard Oracle Down" \
  --condition-display-name="Health check failed" \
  --condition-threshold-value=1 \
  --condition-threshold-duration=300s
```

### 2. Logging

```bash
# View logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=alpenguard-oracle" \
  --limit=50 \
  --format=json

# Create log-based metric for errors
gcloud logging metrics create oracle_errors \
  --description="Count of Oracle errors" \
  --log-filter='resource.type="cloud_run_revision" AND resource.labels.service_name="alpenguard-oracle" AND severity>=ERROR'
```

### 3. Tracing (Cloud Trace)

Add to Oracle `Cargo.toml`:
```toml
opentelemetry = "0.21"
opentelemetry-otlp = "0.14"
tracing-opentelemetry = "0.22"
```

### 4. Metrics Dashboard

Create custom dashboard in Cloud Monitoring:
- Request rate (per endpoint)
- Error rate (4xx, 5xx)
- Latency (p50, p95, p99)
- KMS API calls
- Storage operations
- Active tenants

---

## Security Hardening

### 1. Network Security

```bash
# Restrict Cloud Run ingress
gcloud run services update alpenguard-oracle \
  --ingress=all \
  --region=us-central1

# Enable VPC connector (for private GCS/KMS access)
gcloud compute networks vpc-access connectors create alpenguard-connector \
  --region=us-central1 \
  --network=default \
  --range=10.8.0.0/28

gcloud run services update alpenguard-oracle \
  --vpc-connector=alpenguard-connector \
  --region=us-central1
```

### 2. Secret Rotation

```bash
# Rotate KMS key
gcloud kms keys versions create \
  --location=us-central1 \
  --keyring=alpenguard \
  --key=oracle-master-key \
  --primary

# Rotate service account key (every 90 days)
gcloud iam service-accounts keys create new-key.json \
  --iam-account=alpenguard-oracle@$PROJECT_ID.iam.gserviceaccount.com

gcloud secrets versions add alpenguard-kms-sa-json \
  --data-file=new-key.json

rm new-key.json
```

### 3. Audit Logging

```bash
# Enable Data Access audit logs
gcloud logging write audit-config \
  --severity=INFO \
  --payload-type=json \
  --payload='{"auditConfigs":[{"service":"cloudkms.googleapis.com","auditLogConfigs":[{"logType":"DATA_READ"},{"logType":"DATA_WRITE"}]}]}'
```

---

## Backup & Disaster Recovery

### 1. Database Backups (GCS)

```bash
# Create backup bucket
gsutil mb -l us-central1 gs://alpenguard-backups

# Enable versioning
gsutil versioning set on gs://alpenguard-backups

# Set lifecycle policy (retain for 90 days)
cat > lifecycle.json <<EOF
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "Delete"},
        "condition": {"age": 90}
      }
    ]
  }
}
EOF

gsutil lifecycle set lifecycle.json gs://alpenguard-backups
```

### 2. Disaster Recovery Plan

**RTO (Recovery Time Objective):** 1 hour  
**RPO (Recovery Point Objective):** 15 minutes

**Recovery Steps:**
1. Deploy Oracle to backup region (us-east1)
2. Restore data from GCS backups
3. Update DNS to point to backup region
4. Verify health checks pass
5. Notify users of recovery

---

## Operational Runbook

### Common Operations

#### Scale Up/Down

```bash
# Scale up
gcloud run services update alpenguard-oracle \
  --min-instances=5 \
  --max-instances=50 \
  --region=us-central1

# Scale down
gcloud run services update alpenguard-oracle \
  --min-instances=1 \
  --max-instances=10 \
  --region=us-central1
```

#### View Logs

```bash
# Real-time logs
gcloud run services logs tail alpenguard-oracle --region=us-central1

# Filter by severity
gcloud logging read "resource.type=cloud_run_revision AND severity>=ERROR" --limit=100
```

#### Rollback Deployment

```bash
# List revisions
gcloud run revisions list --service=alpenguard-oracle --region=us-central1

# Rollback to previous revision
gcloud run services update-traffic alpenguard-oracle \
  --to-revisions=REVISION_NAME=100 \
  --region=us-central1
```

#### Rotate DEK for Tenant

```bash
# Call rotation endpoint (implement in Oracle)
curl -X POST https://oracle.alpenguard.io/v1/admin/rotate-dek \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "acme-corp"}'
```

### Incident Response

1. **High Error Rate**
   - Check Cloud Monitoring dashboard
   - Review error logs
   - Verify OIDC provider status
   - Check KMS quota limits

2. **High Latency**
   - Check Cloud Trace for slow requests
   - Verify storage backend performance
   - Check KMS API latency
   - Scale up instances if needed

3. **Data Loss**
   - Restore from GCS backups
   - Verify data integrity
   - Notify affected tenants
   - File incident report

---

## Performance Optimization

### 1. Enable HTTP/2

Cloud Run automatically uses HTTP/2 - no configuration needed.

### 2. Connection Pooling

Oracle uses `reqwest` with connection pooling enabled by default.

### 3. Caching

- **DEK Cache**: 1 hour TTL (configurable via `ALPENGUARD_KMS_CACHE_TTL_SECS`)
- **JWKS Cache**: 5 minutes TTL (configurable via `ALPENGUARD_OIDC_JWKS_TTL_SECS`)
- **GCP Access Token**: Automatic refresh before expiry

### 4. Rate Limiting

Configure per environment:
- **Development**: 25 RPS
- **Staging**: 100 RPS
- **Production**: 500 RPS

---

## Cost Optimization

### Estimated Monthly Costs (1000 tenants, 1M traces/month)

| Service | Cost |
|---------|------|
| Cloud Run (Oracle) | $50-100 |
| Cloud KMS | $10-20 |
| GCS Storage | $20-50 |
| Cloud Monitoring | $10-20 |
| **Total** | **$90-190/month** |

### Cost Reduction Tips

1. Use Cloud Run min-instances=0 for dev/staging
2. Enable GCS lifecycle policies to delete old traces
3. Use Cloudflare R2 instead of GCS (cheaper egress)
4. Batch KMS operations to reduce API calls

---

## Support & Troubleshooting

### Health Checks

```bash
# Oracle health
curl https://oracle.alpenguard.io/healthz

# Console health
curl https://console.alpenguard.io

# Solana program (via RPC)
solana program show ALPG11111111111111111111111111111111111111
```

### Debug Mode

```bash
# Enable debug logging
gcloud run services update alpenguard-oracle \
  --set-env-vars="RUST_LOG=debug" \
  --region=us-central1
```

### Contact

- **GitHub Issues**: https://github.com/AlpenGuard/alpenguard-security-framework/issues
- **Security**: See `SECURITY.md`
- **Community**: GitHub Discussions

---

## Checklist: Production Readiness

- [ ] KMS key created and permissions granted
- [ ] Service account created with least-privilege IAM
- [ ] Secrets stored in Secret Manager
- [ ] Oracle deployed to Cloud Run
- [ ] Console deployed to CDN
- [ ] Solana programs deployed to mainnet
- [ ] Monitoring and alerting configured
- [ ] Backup and disaster recovery tested
- [ ] Security hardening applied
- [ ] Load testing completed
- [ ] Documentation reviewed
- [ ] Incident response plan documented
- [ ] On-call rotation established

**AlpenGuard is production-ready when all items are checked.** ✅
