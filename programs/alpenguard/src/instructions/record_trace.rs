use anchor_lang::prelude::*;

use crate::error::AlpenGuardError;
use crate::state::KernelConfig;

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct RecordTraceParams {
    pub trace_id: [u8; 16],
    pub event_code: u32,
    pub payload_hash: [u8; 32],
}

#[derive(Accounts)]
#[instruction(params: RecordTraceParams)]
pub struct RecordTrace<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"kernel", kernel_config.authority.as_ref()],
        bump = kernel_config.bump,
        has_one = authority @ AlpenGuardError::Unauthorized
    )]
    pub kernel_config: Account<'info, KernelConfig>,
}

pub fn record_trace(ctx: Context<RecordTrace>, params: RecordTraceParams) -> Result<()> {
    if params.event_code == 0 {
        return err!(AlpenGuardError::InvalidInput);
    }

    let cfg = &mut ctx.accounts.kernel_config;
    cfg.trace_seq = cfg.trace_seq.saturating_add(1);

    // Note: Phase 1: on-chain trace anchoring only. Full trace payload is kept off-chain.
    // We emit an event with hashes so off-chain systems can prove integrity.
    emit!(TraceRecorded {
        trace_seq: cfg.trace_seq,
        trace_id: params.trace_id,
        event_code: params.event_code,
        payload_hash: params.payload_hash,
    });

    Ok(())
}

#[event]
pub struct TraceRecorded {
    pub trace_seq: u64,
    pub trace_id: [u8; 16],
    pub event_code: u32,
    pub payload_hash: [u8; 32],
}
