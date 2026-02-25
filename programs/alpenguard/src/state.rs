use anchor_lang::prelude::*;

#[account]
pub struct KernelConfig {
    pub authority: Pubkey,
    pub trace_seq: u64,
    pub bump: u8,
}

impl KernelConfig {
    pub const SPACE: usize = 8 + 32 + 8 + 1;
}
