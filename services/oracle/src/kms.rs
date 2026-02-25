use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use google_cloudkms1::{
    api::{DecryptRequest, EncryptRequest},
    hyper, hyper_rustls, CloudKMS,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};
use yup_oauth2::ServiceAccountAuthenticator;

/// KMS envelope encryption manager
/// 
/// Architecture:
/// - Master Key: GCP KMS key (never leaves KMS)
/// - DEK (Data Encryption Key): Per-tenant AES-256 key
/// - Wrapped DEK: DEK encrypted by KMS master key, stored with ciphertext
/// 
/// Flow:
/// 1. Generate random DEK (32 bytes)
/// 2. Encrypt payload with DEK using AES-256-GCM
/// 3. Encrypt DEK with KMS master key (envelope)
/// 4. Store: wrapped_dek + nonce + ciphertext
/// 
/// Decryption:
/// 1. Extract wrapped_dek from stored record
/// 2. Decrypt wrapped_dek using KMS to get DEK
/// 3. Decrypt ciphertext with DEK using AES-256-GCM
pub struct KmsManager {
    kms_client: Option<Arc<CloudKMS<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>>>,
    key_name: Option<String>,
    dek_cache: Arc<RwLock<HashMap<String, CachedDek>>>,
    cache_ttl: Duration,
}

struct CachedDek {
    dek: [u8; 32],
    wrapped_dek_b64: String,
    created_at: Instant,
}

impl KmsManager {
    /// Create a new KMS manager
    /// 
    /// If GCP KMS is configured, it will use envelope encryption.
    /// Otherwise, falls back to env-provided key (legacy mode).
    pub async fn new(
        kms_key_name: Option<String>,
        service_account_json: Option<String>,
        cache_ttl_secs: u64,
    ) -> Result<Self> {
        let kms_client = if let (Some(key_name), Some(sa_json)) = (&kms_key_name, &service_account_json) {
            info!(key_name = key_name.as_str(), "Initializing GCP KMS client");
            
            let sa_key = yup_oauth2::parse_service_account_key(sa_json)?;
            let auth = ServiceAccountAuthenticator::builder(sa_key)
                .build()
                .await?;
            
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_or_http()
                .enable_http1()
                .build();
            
            let client = hyper::Client::builder().build(https);
            let kms = CloudKMS::new(client, auth);
            
            Some(Arc::new(kms))
        } else {
            warn!("GCP KMS not configured; envelope encryption disabled");
            None
        };

        Ok(Self {
            kms_client,
            key_name: kms_key_name,
            dek_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
        })
    }

    /// Check if KMS is enabled
    pub fn is_enabled(&self) -> bool {
        self.kms_client.is_some() && self.key_name.is_some()
    }

    /// Generate or retrieve cached DEK for a tenant
    /// 
    /// Returns: (dek_bytes, wrapped_dek_b64)
    pub async fn get_or_create_dek(&self, tenant_id: &str) -> Result<([u8; 32], String)> {
        if !self.is_enabled() {
            anyhow::bail!("KMS not enabled");
        }

        // Check cache first
        {
            let cache = self.dek_cache.read().await;
            if let Some(cached) = cache.get(tenant_id) {
                if cached.created_at.elapsed() < self.cache_ttl {
                    return Ok((cached.dek, cached.wrapped_dek_b64.clone()));
                }
            }
        }

        // Generate new DEK
        let mut dek = [0u8; 32];
        getrandom::getrandom(&mut dek)?;

        // Wrap DEK with KMS
        let wrapped_dek_b64 = self.wrap_dek(&dek).await?;

        // Cache it
        {
            let mut cache = self.dek_cache.write().await;
            cache.insert(
                tenant_id.to_string(),
                CachedDek {
                    dek,
                    wrapped_dek_b64: wrapped_dek_b64.clone(),
                    created_at: Instant::now(),
                },
            );
        }

        Ok((dek, wrapped_dek_b64))
    }

    /// Unwrap a DEK using KMS
    pub async fn unwrap_dek(&self, wrapped_dek_b64: &str) -> Result<[u8; 32]> {
        if !self.is_enabled() {
            anyhow::bail!("KMS not enabled");
        }

        let kms = self.kms_client.as_ref().unwrap();
        let key_name = self.key_name.as_ref().unwrap();

        let req = DecryptRequest {
            ciphertext: Some(wrapped_dek_b64.to_string()),
            additional_authenticated_data: None,
            ciphertext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let (_, resp) = kms
            .projects()
            .locations_key_rings_crypto_keys_decrypt(req, key_name)
            .doit()
            .await?;

        let plaintext_b64 = resp.plaintext.ok_or_else(|| anyhow::anyhow!("KMS decrypt returned no plaintext"))?;
        let dek_bytes = B64.decode(plaintext_b64.as_bytes())?;

        if dek_bytes.len() != 32 {
            anyhow::bail!("Unwrapped DEK is not 32 bytes");
        }

        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_bytes);
        Ok(dek)
    }

    /// Wrap a DEK using KMS
    async fn wrap_dek(&self, dek: &[u8; 32]) -> Result<String> {
        let kms = self.kms_client.as_ref().unwrap();
        let key_name = self.key_name.as_ref().unwrap();

        let plaintext_b64 = B64.encode(dek);

        let req = EncryptRequest {
            plaintext: Some(plaintext_b64),
            additional_authenticated_data: None,
            plaintext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let (_, resp) = kms
            .projects()
            .locations_key_rings_crypto_keys_encrypt(req, key_name)
            .doit()
            .await?;

        let wrapped = resp.ciphertext.ok_or_else(|| anyhow::anyhow!("KMS encrypt returned no ciphertext"))?;
        Ok(wrapped)
    }

    /// Rotate DEK for a tenant (invalidate cache)
    pub async fn rotate_dek(&self, tenant_id: &str) {
        let mut cache = self.dek_cache.write().await;
        cache.remove(tenant_id);
        info!(tenant_id, "DEK rotated (cache invalidated)");
    }
}
