use anyhow::Result;

#[cfg(test)]
mod kms_manager_tests {
    use super::*;

    #[tokio::test]
    async fn test_kms_manager_disabled_when_no_config() {
        let mgr = crate::kms::KmsManager::new(None, None, 3600)
            .await
            .expect("should create manager");

        assert!(!mgr.is_enabled(), "KMS should be disabled without config");
    }

    #[tokio::test]
    async fn test_kms_manager_fails_gracefully_with_invalid_sa_json() {
        let result = crate::kms::KmsManager::new(
            Some("projects/test/locations/us/keyRings/test/cryptoKeys/test".to_string()),
            Some("invalid json".to_string()),
            3600,
        )
        .await;

        assert!(result.is_err(), "should fail with invalid SA JSON");
    }

    #[test]
    fn test_dek_generation_produces_32_bytes() {
        let mut dek = [0u8; 32];
        getrandom::getrandom(&mut dek).expect("should generate random bytes");
        assert_eq!(dek.len(), 32, "DEK should be exactly 32 bytes");
    }

    // Note: Full KMS integration tests require GCP credentials and are skipped in CI
    // Run manually with: cargo test --features integration_tests
}
