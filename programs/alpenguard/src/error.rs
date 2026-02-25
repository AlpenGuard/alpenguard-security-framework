use anchor_lang::prelude::*;

#[error_code]
pub enum AlpenGuardError {
    #[msg("Invalid input")]
    InvalidInput,

    #[msg("Unauthorized")]
    Unauthorized,
}
