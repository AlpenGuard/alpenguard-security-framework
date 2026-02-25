use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use std::{path::{Path, PathBuf}};
use std::{time::{Duration, Instant}};
use tokio::sync::RwLock;
use tracing::{info, warn};
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    set_header::SetResponseHeaderLayer,
};
use urlencoding::encode as url_encode;
use aws_credential_types::Credentials;
use aws_sdk_s3::primitives::ByteStream;
use aws_types::region::Region;

#[derive(Clone)]
struct AppState {
    kms_key_present: bool,
    aes_key_32: Option<[u8; 32]>,
    auth: AuthConfig,
    http: Client,
    data_dir: PathBuf,
    storage: StorageBackend,
    max_trace_payload_bytes: usize,
}

#[derive(Clone)]
enum StorageBackend {
    Fs,
    Gcs {
        bucket: String,
        prefix: String,
    },
    S3 {
        client: aws_sdk_s3::Client,
        bucket: String,
        prefix: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
struct GcpTokenResponse {
    access_token: String,
    expires_in: i64,
    token_type: String,
}

struct GcpTokenCache {
    access_token: String,
    expires_at: Instant,
}

static GCP_TOKEN_CACHE: Lazy<RwLock<Option<GcpTokenCache>>> = Lazy::new(|| RwLock::new(None));

#[derive(Clone)]
struct AuthConfig {
    enabled: bool,
    issuer: String,
    audience: String,
    jwks_url: String,
}

#[derive(Clone, Copy, Debug)]
enum Action {
    TracesIngest,
    TracesRead,
}

impl Action {
    fn required_scope(&self) -> &'static str {
        match self {
            Action::TracesIngest => "traces:ingest",
            Action::TracesRead => "traces:read",
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Action::TracesIngest => "traces.ingest",
            Action::TracesRead => "traces.read",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: serde_json::Value,
    exp: usize,
    iat: Option<usize>,
    scope: Option<String>,
    permissions: Option<Vec<String>>,
    #[serde(default)]
    tenant_id: Option<String>,
}

fn aud_matches_config(aud: &serde_json::Value, expected: &str) -> bool {
    match aud {
        serde_json::Value::String(s) => s == expected,
        serde_json::Value::Array(items) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

#[derive(Clone, Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Clone, Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    jwk_use: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

struct JwksCache {
    fetched_at: Instant,
    jwks: Jwks,
}

static JWKS_CACHE: Lazy<RwLock<Option<JwksCache>>> = Lazy::new(|| RwLock::new(None));

#[derive(Debug, Deserialize)]
struct TraceIngestRequest {
    tenant_id: String,
    trace_id: String,
    span_id: String,
    ts_unix_ms: i64,
    agent_id: String,
    event_type: String,
    payload_b64: String,
    payload_sha256_b64: String,
}

#[derive(Debug, Serialize)]
struct TraceIngestResponse {
    accepted: bool,
}

#[derive(Debug, Serialize)]
struct TraceSummary {
    tenant_id: String,
    trace_id: String,
    span_id: String,
    ts_unix_ms: i64,
    agent_id: String,
    event_type: String,
    payload_sha256_b64: String,
}

#[derive(Debug, Serialize)]
struct TraceListResponse {
    items: Vec<TraceSummary>,
}

#[derive(Debug, Deserialize)]
struct TraceGetRequest {
    tenant_id: String,
    trace_id: String,
    span_id: String,
}

#[derive(Debug, Serialize)]
struct TraceGetResponse {
    trace: TraceSummary,
    payload_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TraceRecord {
    trace: TraceSummary,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let max_body_bytes: usize = std::env::var("ALPENGUARD_MAX_BODY_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(262_144);

    let max_trace_payload_bytes: usize = std::env::var("ALPENGUARD_MAX_TRACE_PAYLOAD_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(131_072);

    let http_timeout_secs: u64 = std::env::var("ALPENGUARD_HTTP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    let http_connect_timeout_secs: u64 = std::env::var("ALPENGUARD_HTTP_CONNECT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    let aes_key_32: Option<[u8; 32]> = match std::env::var("ALPENGUARD_KMS_KEY_B64") {
        Ok(key_b64) => {
            let key_bytes = B64.decode(key_b64.as_bytes())?;
            if key_bytes.len() != 32 {
                anyhow::bail!("ALPENGUARD_KMS_KEY_B64 must decode to 32 bytes for AES-256-GCM");
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            Some(key)
        }
        Err(_) => None,
    };

    let kms_key_present = aes_key_32.is_some();
    if !kms_key_present {
        warn!("ALPENGUARD_KMS_KEY_B64 not set; trace ingestion will be rejected to avoid plaintext storage.");
    }

    let auth = AuthConfig {
        enabled: std::env::var("ALPENGUARD_OIDC_ENABLED").ok().as_deref() == Some("1"),
        issuer: std::env::var("ALPENGUARD_OIDC_ISSUER").unwrap_or_default(),
        audience: std::env::var("ALPENGUARD_OIDC_AUDIENCE").unwrap_or_default(),
        jwks_url: std::env::var("ALPENGUARD_OIDC_JWKS_URL").unwrap_or_default(),
    };

    if auth.enabled {
        if auth.issuer.is_empty() || auth.audience.is_empty() || auth.jwks_url.is_empty() {
            anyhow::bail!(
                "OIDC enabled but missing env vars. Require ALPENGUARD_OIDC_ISSUER, ALPENGUARD_OIDC_AUDIENCE, ALPENGUARD_OIDC_JWKS_URL"
            );
        }
        if !auth.jwks_url.starts_with("https://") {
            anyhow::bail!(
                "ALPENGUARD_OIDC_JWKS_URL must use HTTPS to prevent SSRF attacks. Got: {}",
                auth.jwks_url
            );
        }
        info!("OIDC auth enabled for protected endpoints");
    } else {
        let allow_insecure = std::env::var("ALPENGUARD_ALLOW_INSECURE").ok().as_deref() == Some("1");
        if !allow_insecure {
            anyhow::bail!(
                "OIDC auth is disabled. Refusing to start without explicit ALPENGUARD_ALLOW_INSECURE=1 (unsafe for public deployments)."
            );
        }
        warn!("OIDC auth disabled via ALPENGUARD_ALLOW_INSECURE=1. Do not use this mode in public deployments.");
    }

    let data_dir = std::env::var("ALPENGUARD_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/alpenguard-data"));

    let storage = if let Ok(bucket) = std::env::var("ALPENGUARD_S3_BUCKET") {
        if !bucket.trim().is_empty() {
            let prefix = std::env::var("ALPENGUARD_S3_PREFIX").unwrap_or_else(|_| "alpenguard".to_string());
            let endpoint = std::env::var("ALPENGUARD_S3_ENDPOINT").unwrap_or_else(|_| "".to_string());
            let region = std::env::var("ALPENGUARD_S3_REGION").unwrap_or_else(|_| "auto".to_string());
            let access_key_id = std::env::var("ALPENGUARD_S3_ACCESS_KEY_ID").unwrap_or_else(|_| "".to_string());
            let secret_access_key = std::env::var("ALPENGUARD_S3_SECRET_ACCESS_KEY").unwrap_or_else(|_| "".to_string());

            if endpoint.trim().is_empty() || access_key_id.trim().is_empty() || secret_access_key.trim().is_empty() {
                anyhow::bail!("S3 storage enabled but missing ALPENGUARD_S3_ENDPOINT / ALPENGUARD_S3_ACCESS_KEY_ID / ALPENGUARD_S3_SECRET_ACCESS_KEY");
            }

            let s3 = build_s3_client(&endpoint, &region, &access_key_id, &secret_access_key).await?;
            info!(bucket = bucket.as_str(), prefix = prefix.as_str(), "S3-compatible storage enabled");
            StorageBackend::S3 {
                client: s3,
                bucket,
                prefix,
            }
        } else {
            StorageBackend::Fs
        }
    } else if let Ok(bucket) = std::env::var("ALPENGUARD_GCS_BUCKET") {
        if !bucket.trim().is_empty() {
            let prefix = std::env::var("ALPENGUARD_GCS_PREFIX").unwrap_or_else(|_| "alpenguard".to_string());
            info!(bucket = bucket.as_str(), prefix = prefix.as_str(), "GCS storage enabled");
            StorageBackend::Gcs { bucket, prefix }
        } else {
            StorageBackend::Fs
        }
    } else {
        info!(data_dir = data_dir.display().to_string(), "filesystem storage enabled");
        StorageBackend::Fs
    };

    let state = Arc::new(AppState {
        kms_key_present,
        aes_key_32,
        auth,
        http: Client::builder()
            .timeout(Duration::from_secs(http_timeout_secs))
            .connect_timeout(Duration::from_secs(http_connect_timeout_secs))
            .build()?,
        data_dir,
        storage,
        max_trace_payload_bytes,
    });

    let rate_limit_per_second: u32 = std::env::var("ALPENGUARD_RATELIMIT_RPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);

    let governor_conf = GovernorConfigBuilder::default()
        .per_second(rate_limit_per_second)
        .burst_size(rate_limit_per_second)
        .finish()
        .expect("governor config");

    let behind_proxy = std::env::var("ALPENGUARD_BEHIND_PROXY").ok().as_deref() == Some("1");
    let allow_proxy_rate_limit = std::env::var("ALPENGUARD_ALLOW_PROXY_RATE_LIMIT").ok().as_deref() == Some("1");
    if behind_proxy && !allow_proxy_rate_limit {
        anyhow::bail!(
            "ALPENGUARD_BEHIND_PROXY=1 set but rate-limiting keying may be incorrect behind proxies. Set ALPENGUARD_ALLOW_PROXY_RATE_LIMIT=1 to acknowledge, or disable proxy mode."
        );
    }
    if behind_proxy {
        warn!("Running behind proxy; ensure the server sees real client IPs for rate limiting.");
    }

    let allowed_origins = std::env::var("ALPENGUARD_CORS_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:5173".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    let cors = CorsLayer::new()
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE])
        .allow_origin(AllowOrigin::list(
            allowed_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect::<Vec<axum::http::HeaderValue>>(),
        ));

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/traces:ingest", post(ingest_trace))
        .route("/v1/traces:list", get(list_traces))
        .route("/v1/traces:get", post(get_trace))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(GovernorLayer { config: Arc::new(governor_conf) })
        .layer(cors)
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::HeaderName::from_static("referrer-policy"),
            axum::http::HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::HeaderName::from_static("x-frame-options"),
            axum::http::HeaderValue::from_static("DENY"),
        ))
        .with_state(state);

    let addr: SocketAddr = match std::env::var("ALPENGUARD_BIND") {
        Ok(v) => v.parse()?,
        Err(_) => {
            let port: u16 = std::env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8787);
            SocketAddr::from(([0, 0, 0, 0], port))
        }
    };

    info!(%addr, "alpenguard-oracle listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn healthz() -> (StatusCode, Json<HealthResponse>) {
    (StatusCode::OK, Json(HealthResponse { ok: true }))
}

async fn ingest_trace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TraceIngestRequest>,
) -> (StatusCode, Json<TraceIngestResponse>) {
    let mut subject_sub: Option<String> = None;
    let mut authorized_tenant: Option<String> = None;
    if state.auth.enabled {
        match authorize_request(&state, &headers, Action::TracesIngest).await {
            Ok(claims) => {
                audit_event(Action::TracesIngest, "allow", Some(&claims.sub), None);
                subject_sub = Some(claims.sub);
                authorized_tenant = claims.tenant_id;
            }
            Err(code) => {
                audit_event(Action::TracesIngest, "deny", None, Some(code.as_u16()));
                return (code, Json(TraceIngestResponse { accepted: false }));
            }
        }
    }

    if !state.kms_key_present {
        return (StatusCode::FAILED_DEPENDENCY, Json(TraceIngestResponse { accepted: false }));
    }

    // Phase 1 skeleton:
    // - Validate request shape
    // - Verify payload hash
    // - Persist encrypted at rest (planned: KMS envelope)
    // - Emit to trace pipeline (planned: OpenTelemetry collector)

    if req.tenant_id.is_empty() || req.trace_id.is_empty() || req.span_id.is_empty() || req.agent_id.is_empty() || req.event_type.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(TraceIngestResponse { accepted: false }));
    }

    if state.auth.enabled {
        if let Some(ref auth_tenant) = authorized_tenant {
            if auth_tenant != &req.tenant_id {
                audit_event(Action::TracesIngest, "tenant_mismatch", None, Some(StatusCode::FORBIDDEN.as_u16()));
                return (StatusCode::FORBIDDEN, Json(TraceIngestResponse { accepted: false }));
            }
        }
    }

    let payload = match B64.decode(req.payload_b64.as_bytes()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(TraceIngestResponse { accepted: false })),
    };

    if payload.len() > state.max_trace_payload_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(TraceIngestResponse { accepted: false }));
    }

    let expected_hash = match B64.decode(req.payload_sha256_b64.as_bytes()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(TraceIngestResponse { accepted: false })),
    };

    if expected_hash.len() != 32 {
        return (StatusCode::BAD_REQUEST, Json(TraceIngestResponse { accepted: false }));
    }

    let actual_hash = sha256(&payload);
    if actual_hash.as_slice() != expected_hash.as_slice() {
        audit_event(Action::TracesIngest, "reject_hash_mismatch", None, Some(StatusCode::UNPROCESSABLE_ENTITY.as_u16()));
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(TraceIngestResponse { accepted: false }));
    }

    if let Err(e) = persist_trace_record(&state, &req, &payload).await {
        warn!(error = %e, "persist_trace_record failed");
        audit_event(Action::TracesIngest, "error_persist", None, Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()));
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(TraceIngestResponse { accepted: false }));
    }

    let accepted_subject = subject_sub.as_deref().or(Some(req.agent_id.as_str()));
    audit_event(Action::TracesIngest, "accepted", accepted_subject, None);
    (StatusCode::ACCEPTED, Json(TraceIngestResponse { accepted: true }))
}

async fn list_traces(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<TraceListResponse>) {
    let mut authorized_tenant: Option<String> = None;
    if state.auth.enabled {
        match authorize_request(&state, &headers, Action::TracesRead).await {
            Ok(claims) => {
                audit_event(Action::TracesRead, "allow", Some(&claims.sub), None);
                authorized_tenant = claims.tenant_id;
            }
            Err(code) => {
                audit_event(Action::TracesRead, "deny", None, Some(code.as_u16()));
            return (code, Json(TraceListResponse { items: vec![] }));
            }
        }
    }

    let mut items: Vec<TraceSummary> = match list_trace_summaries(&state).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "list_trace_summaries failed");
            vec![]
        }
    };

    if state.auth.enabled {
        if let Some(ref tenant) = authorized_tenant {
            items.retain(|item| &item.tenant_id == tenant);
        }
    }

    items.sort_by(|a, b| b.ts_unix_ms.cmp(&a.ts_unix_ms));
    if items.len() > 500 {
        items.truncate(500);
    }

    (StatusCode::OK, Json(TraceListResponse { items }))
}

async fn get_trace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TraceGetRequest>,
) -> impl IntoResponse {
    let mut authorized_tenant: Option<String> = None;
    if state.auth.enabled {
        match authorize_request(&state, &headers, Action::TracesRead).await {
            Ok(claims) => {
                audit_event(Action::TracesRead, "allow", Some(&claims.sub), None);
                authorized_tenant = claims.tenant_id;
            }
            Err(code) => {
                audit_event(Action::TracesRead, "deny", None, Some(code.as_u16()));
                return (code, Json(serde_json::json!({"error":"unauthorized"})));
            }
        }
    }

    if req.tenant_id.is_empty() || req.trace_id.is_empty() || req.span_id.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid_input"})));
    }

    if state.auth.enabled {
        if let Some(ref auth_tenant) = authorized_tenant {
            if auth_tenant != &req.tenant_id {
                audit_event(Action::TracesRead, "tenant_mismatch", None, Some(StatusCode::FORBIDDEN.as_u16()));
                return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden"})));
            }
        }
    }

    let bytes = match load_trace_record_bytes(&state, &req.tenant_id, &req.trace_id, &req.span_id).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            audit_event(Action::TracesRead, "not_found", None, Some(StatusCode::NOT_FOUND.as_u16()));
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"not_found"})));
        }
        Err(e) => {
            warn!(error = %e, "load_trace_record_bytes failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"load_failed"})));
        }
    };
    let rec: TraceRecord = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"corrupt_record"}))),
    };

    if !state.kms_key_present {
        return (StatusCode::FAILED_DEPENDENCY, Json(serde_json::json!({"error":"kms_key_missing"})));
    }

    let payload = match decrypt_payload_from_record(&state, &rec).await {
        Ok(p) => p,
        Err(_) => {
            audit_event(Action::TracesRead, "decrypt_failed", None, Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()));
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"decrypt_failed"})));
        }
    };

    if payload.len() > state.max_trace_payload_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(serde_json::json!({"error":"payload_too_large"})));
    }

    let resp = TraceGetResponse {
        trace: rec.trace,
        payload_b64: B64.encode(payload),
    };

    audit_event(Action::TracesRead, "ok", None, None);

    (StatusCode::OK, Json(resp))
}

fn traces_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("traces")
}

fn trace_path(data_dir: &Path, tenant_id: &str, trace_id: &str, span_id: &str) -> PathBuf {
    traces_dir(data_dir)
        .join(sanitize_id(tenant_id))
        .join(format!("{}_{}.json", sanitize_id(trace_id), sanitize_id(span_id)))
}

fn trace_object_name(prefix: &str, tenant_id: &str, trace_id: &str, span_id: &str) -> String {
    format!(
        "{}/traces/{}/{}_{}.json",
        sanitize_id(prefix),
        sanitize_id(tenant_id),
        sanitize_id(trace_id),
        sanitize_id(span_id)
    )
}

fn sanitize_id(input: &str) -> String {
    input
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

async fn persist_trace_record(state: &AppState, req: &TraceIngestRequest, payload: &[u8]) -> anyhow::Result<()> {
    match &state.storage {
        StorageBackend::Fs => {
            tokio::fs::create_dir_all(traces_dir(&state.data_dir)).await?;
        }
        StorageBackend::Gcs { .. } => {}
    }

    let key = state
        .aes_key_32
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("kms key missing"))?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())?;
    let nonce = random_nonce_12();
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), payload)?;

    let trace = TraceSummary {
        tenant_id: req.tenant_id.clone(),
        trace_id: req.trace_id.clone(),
        span_id: req.span_id.clone(),
        ts_unix_ms: req.ts_unix_ms,
        agent_id: req.agent_id.clone(),
        event_type: req.event_type.clone(),
        payload_sha256_b64: req.payload_sha256_b64.clone(),
    };

    let rec = TraceRecord {
        trace,
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(ciphertext),
    };

    let bytes = serde_json::to_vec(&rec)?;

    store_trace_record_bytes(state, &req.tenant_id, &req.trace_id, &req.span_id, bytes).await?;
    Ok(())
}

async fn decrypt_payload_from_record(state: &AppState, rec: &TraceRecord) -> anyhow::Result<Vec<u8>> {
    let key = state
        .aes_key_32
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("kms key missing"))?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())?;

    let nonce = B64.decode(rec.nonce_b64.as_bytes())?;
    if nonce.len() != 12 {
        anyhow::bail!("invalid nonce length");
    }
    let ciphertext = B64.decode(rec.ciphertext_b64.as_bytes())?;
    let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())?;
    Ok(plaintext)
}

async fn store_trace_record_bytes(state: &AppState, tenant_id: &str, trace_id: &str, span_id: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
    match &state.storage {
        StorageBackend::Fs => {
            let path = trace_path(&state.data_dir, tenant_id, trace_id, span_id);
            let parent = path.parent().ok_or_else(|| anyhow::anyhow!("invalid path"))?;
            tokio::fs::create_dir_all(parent).await?;
            tokio::fs::write(path, bytes).await?;
            Ok(())
        }
        StorageBackend::Gcs { bucket, prefix } => {
            let object = trace_object_name(prefix, tenant_id, trace_id, span_id);
            gcs_put_object(state, bucket, &object, bytes).await
        }
        StorageBackend::S3 { client, bucket, prefix } => {
            let key = trace_object_name(prefix, tenant_id, trace_id, span_id);
            s3_put_object(client, bucket, &key, bytes).await
        }
    }
}

async fn load_trace_record_bytes(state: &AppState, tenant_id: &str, trace_id: &str, span_id: &str) -> anyhow::Result<Option<Vec<u8>>> {
    match &state.storage {
        StorageBackend::Fs => {
            let path = trace_path(&state.data_dir, tenant_id, trace_id, span_id);
            match tokio::fs::read(&path).await {
                Ok(b) => Ok(Some(b)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.into()),
            }
        }
        StorageBackend::Gcs { bucket, prefix } => {
            let object = trace_object_name(prefix, tenant_id, trace_id, span_id);
            gcs_get_object(state, bucket, &object).await
        }
        StorageBackend::S3 { client, bucket, prefix } => {
            let key = trace_object_name(prefix, tenant_id, trace_id, span_id);
            s3_get_object(client, bucket, &key).await
        }
    }
}

async fn list_trace_summaries(state: &AppState) -> anyhow::Result<Vec<TraceSummary>> {
    match &state.storage {
        StorageBackend::Fs => {
            let dir = traces_dir(&state.data_dir);
            let mut items: Vec<TraceSummary> = Vec::new();

            let mut tenant_dirs = match tokio::fs::read_dir(&dir).await {
                Ok(v) => v,
                Err(_) => return Ok(items),
            };

            loop {
                let tenant_entry = match tenant_dirs.next_entry().await {
                    Ok(Some(e)) => e,
                    Ok(None) => break,
                    Err(_) => break,
                };

                if tenant_entry.file_type().await.ok().map(|t| t.is_dir()) != Some(true) {
                    continue;
                }

                let mut trace_files = match tokio::fs::read_dir(tenant_entry.path()).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                loop {
                    let entry = match trace_files.next_entry().await {
                        Ok(Some(e)) => e,
                        Ok(None) => break,
                        Err(_) => break,
                    };

                    if entry.file_type().await.ok().map(|t| t.is_file()) != Some(true) {
                        continue;
                    }

                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) != Some("json") {
                        continue;
                    }

                    let bytes = match tokio::fs::read(&path).await {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    let rec: TraceRecord = match serde_json::from_slice(&bytes) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    items.push(rec.trace);
                }
            }

            Ok(items)
        }
        StorageBackend::Gcs { bucket, prefix } => {
            let object_prefix = format!("{}/traces/", sanitize_id(prefix));
            let names = gcs_list_objects(state, bucket, &object_prefix, 500).await?;

            let mut out: Vec<TraceSummary> = Vec::new();
            for name in names.into_iter().take(200) {
                let Some(bytes) = gcs_get_object(state, bucket, &name).await? else {
                    continue;
                };
                let rec: TraceRecord = match serde_json::from_slice(&bytes) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                out.push(rec.trace);
            }

            Ok(out)
        }
        StorageBackend::S3 { client, bucket, prefix } => {
            let object_prefix = format!("{}/traces/", sanitize_id(prefix));
            let names = s3_list_objects(client, bucket, &object_prefix, 500).await?;

            let mut out: Vec<TraceSummary> = Vec::new();
            for key in names.into_iter().take(200) {
                let Some(bytes) = s3_get_object(client, bucket, &key).await? else {
                    continue;
                };
                let rec: TraceRecord = match serde_json::from_slice(&bytes) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                out.push(rec.trace);
            }

            Ok(out)
        }
    }
}

async fn build_s3_client(endpoint: &str, region: &str, access_key_id: &str, secret_access_key: &str) -> anyhow::Result<aws_sdk_s3::Client> {
    let creds = Credentials::new(
        access_key_id.to_string(),
        secret_access_key.to_string(),
        None,
        None,
        "alpenguard-static",
    );

    let shared = aws_config::from_env()
        .region(Region::new(region.to_string()))
        .credentials_provider(creds)
        .load()
        .await;

    let s3_conf = aws_sdk_s3::config::Builder::from(&shared)
        .endpoint_url(endpoint)
        .build();

    Ok(aws_sdk_s3::Client::from_conf(s3_conf))
}

async fn s3_put_object(client: &aws_sdk_s3::Client, bucket: &str, key: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .content_type("application/json")
        .body(ByteStream::from(bytes))
        .send()
        .await?;
    Ok(())
}

async fn s3_get_object(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let res = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await;

    let out = match res {
        Ok(v) => v,
        Err(e) => {
            // For S3-compatible APIs, missing keys should map to a "NoSuchKey" service error.
            let msg = format!("{e}");
            if msg.contains("NoSuchKey") || msg.contains("NotFound") {
                return Ok(None);
            }
            return Err(e.into());
        }
    };

    let data = out.body.collect().await?.into_bytes().to_vec();
    Ok(Some(data))
}

async fn s3_list_objects(client: &aws_sdk_s3::Client, bucket: &str, prefix: &str, max_keys: i32) -> anyhow::Result<Vec<String>> {
    let resp = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .max_keys(max_keys)
        .send()
        .await?;

    Ok(resp
        .contents
        .unwrap_or_default()
        .into_iter()
        .filter_map(|o| o.key)
        .collect())
}

async fn gcs_put_object(state: &AppState, bucket: &str, object: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
    let token = gcp_access_token(state).await?;
    let url = format!(
        "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=media&name={}",
        bucket,
        url_encode(object)
    );

    state
        .http
        .post(url)
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

async fn gcs_get_object(state: &AppState, bucket: &str, object: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let token = gcp_access_token(state).await?;
    let url = format!(
        "https://storage.googleapis.com/storage/v1/b/{}/o/{}?alt=media",
        bucket,
        url_encode(object)
    );

    let res = state.http.get(url).bearer_auth(token).send().await?;
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let bytes = res.error_for_status()?.bytes().await?;
    Ok(Some(bytes.to_vec()))
}

#[derive(Debug, Deserialize)]
struct GcsListResponse {
    items: Option<Vec<GcsObject>>,
}

#[derive(Debug, Deserialize)]
struct GcsObject {
    name: String,
}

async fn gcs_list_objects(state: &AppState, bucket: &str, prefix: &str, max_results: usize) -> anyhow::Result<Vec<String>> {
    let token = gcp_access_token(state).await?;
    let url = format!(
        "https://storage.googleapis.com/storage/v1/b/{}/o?prefix={}&maxResults={}",
        bucket,
        url_encode(prefix),
        max_results
    );

    let resp: GcsListResponse = state
        .http
        .get(url)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(resp
        .items
        .unwrap_or_default()
        .into_iter()
        .map(|o| o.name)
        .collect())
}

async fn gcp_access_token(state: &AppState) -> anyhow::Result<String> {
    {
        let guard = GCP_TOKEN_CACHE.read().await;
        if let Some(cached) = guard.as_ref() {
            if Instant::now() < cached.expires_at {
                return Ok(cached.access_token.clone());
            }
        }
    }

    let resp: GcpTokenResponse = state
        .http
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let expires_at = Instant::now() + Duration::from_secs((resp.expires_in.max(60) as u64).saturating_sub(30));

    let mut guard = GCP_TOKEN_CACHE.write().await;
    *guard = Some(GcpTokenCache {
        access_token: resp.access_token.clone(),
        expires_at,
    });

    Ok(resp.access_token)
}

fn random_nonce_12() -> [u8; 12] {
    // Avoid introducing extra deps in Phase 1; use OS RNG via getrandom.
    // jsonwebtoken already pulls in rand in many builds, but we keep this explicit.
    let mut out = [0u8; 12];
    getrandom::getrandom(&mut out).expect("os rng");
    out
}

async fn authorize_request(state: &AppState, headers: &HeaderMap, action: Action) -> Result<Claims, StatusCode> {
    let authz = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = authz
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .trim();

    if token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let header = decode_header(token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    if header.alg != Algorithm::RS256 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let kid = header.kid.ok_or(StatusCode::UNAUTHORIZED)?;
    let jwks = get_jwks(state).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid.as_deref() == Some(kid.as_str()))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if jwk.kty != "RSA" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let n = jwk.n.as_deref().ok_or(StatusCode::UNAUTHORIZED)?;
    let e = jwk.e.as_deref().ok_or(StatusCode::UNAUTHORIZED)?;
    let key = DecodingKey::from_rsa_components(n, e).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[state.auth.issuer.as_str()]);
    validation.set_audience(&[state.auth.audience.as_str()]);

    let data = decode::<Claims>(token, &key, &validation).map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !aud_matches_config(&data.claims.aud, state.auth.audience.as_str()) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !claims_has_scope(&data.claims, action.required_scope()) {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(data.claims)
}

fn audit_event(action: Action, outcome: &'static str, subject: Option<&str>, http_status: Option<u16>) {
    match (subject, http_status) {
        (Some(sub), Some(code)) => info!(action = action.as_str(), outcome, subject = sub, http_status = code, "audit"),
        (Some(sub), None) => info!(action = action.as_str(), outcome, subject = sub, "audit"),
        (None, Some(code)) => info!(action = action.as_str(), outcome, http_status = code, "audit"),
        (None, None) => info!(action = action.as_str(), outcome, "audit"),
    }
}

fn claims_has_scope(claims: &Claims, required_scope: &str) -> bool {
    if let Some(scope) = claims.scope.as_deref() {
        if scope.split_whitespace().any(|s| s == required_scope) {
            return true;
        }
    }

    if let Some(perms) = claims.permissions.as_deref() {
        if perms.iter().any(|p| p == required_scope) {
            return true;
        }
    }

    false
}

async fn get_jwks(state: &AppState) -> anyhow::Result<Jwks> {
    let ttl = Duration::from_secs(
        std::env::var("ALPENGUARD_OIDC_JWKS_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300),
    );

    {
        let guard = JWKS_CACHE.read().await;
        if let Some(cached) = guard.as_ref() {
            if cached.fetched_at.elapsed() < ttl {
                return Ok(cached.jwks.clone());
            }
        }
    }

    let jwks: Jwks = state.http.get(&state.auth.jwks_url).send().await?.error_for_status()?.json().await?;

    let mut guard = JWKS_CACHE.write().await;
    *guard = Some(JwksCache {
        fetched_at: Instant::now(),
        jwks: jwks.clone(),
    });

    Ok(jwks)
}
