use anchor_lang::prelude::*;

use crate::error::AlpenGuardError;
use crate::state::KernelConfig;

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializeKernelParams {
    pub authority: Pubkey,
}

#[derive(Accounts)]
#[instruction(params: InitializeKernelParams)]
pub struct InitializeKernel<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = KernelConfig::SPACE,
        seeds = [b"kernel", params.authority.as_ref()],
        bump
    )]
    pub kernel_config: Account<'info, KernelConfig>,

    pub system_program: Program<'info, System>,
}

pub fn initialize_kernel(ctx: Context<InitializeKernel>, params: InitializeKernelParams) -> Result<()> {
    if params.authority == Pubkey::default() {
        return err!(AlpenGuardError::InvalidInput);
    }

    let cfg = &mut ctx.accounts.kernel_config;
    cfg.authority = params.authority;
    cfg.trace_seq = 0;
    cfg.bump = ctx.bumps.kernel_config;

    Ok(())
}
