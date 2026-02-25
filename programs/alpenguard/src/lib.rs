use anchor_lang::prelude::*;

mod error;
mod instructions;
mod state;

use instructions::*;

declare_id!("ALPG11111111111111111111111111111111111111");

#[program]
pub mod alpenguard {
    use super::*;

    pub fn initialize_kernel(ctx: Context<InitializeKernel>, params: InitializeKernelParams) -> Result<()> {
        instructions::initialize_kernel(ctx, params)
    }

    pub fn record_trace(ctx: Context<RecordTrace>, params: RecordTraceParams) -> Result<()> {
        instructions::record_trace(ctx, params)
    }
}
