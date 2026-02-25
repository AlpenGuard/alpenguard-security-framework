use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;

#[cfg(test)]
mod micropayments_tests {
    use super::*;

    #[test]
    fn test_payment_config_space_calculation() {
        // PaymentConfig: 8 (discriminator) + 32 (authority) + 32 (mint) + 32 (treasury) + 8 (price) + 1 (bump)
        let expected_space = 8 + 32 + 32 + 32 + 8 + 1;
        assert_eq!(
            alpenguard_micropayments::PaymentConfig::SPACE,
            expected_space,
            "PaymentConfig SPACE should match calculated size"
        );
    }

    #[test]
    fn test_payment_session_space_calculation() {
        // PaymentSession: 8 (discriminator) + 32 (payer) + 32 (config) + 16 (trace_id) + 8 (amount) + 1 (paid) + 1 (refunded) + 8 (created_at) + 9 (paid_at Option) + 9 (refunded_at Option) + 1 (bump)
        let expected_space = 8 + 32 + 32 + 16 + 8 + 1 + 1 + 8 + 9 + 9 + 1;
        assert_eq!(
            alpenguard_micropayments::PaymentSession::SPACE,
            expected_space,
            "PaymentSession SPACE should match calculated size"
        );
    }

    // Note: Full Anchor integration tests require Solana test validator
    // Run with: anchor test
}
