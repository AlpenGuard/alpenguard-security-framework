use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022, TransferChecked};
use anchor_spl::token_interface::{Mint, TokenAccount};

declare_id!("MPay11111111111111111111111111111111111111");

#[program]
pub mod alpenguard_micropayments {
    use super::*;

    /// Initialize payment config for a service provider
    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        params: InitializeConfigParams,
    ) -> Result<()> {
        let config = &mut ctx.accounts.payment_config;
        config.authority = params.authority;
        config.mint = ctx.accounts.mint.key();
        config.treasury = ctx.accounts.treasury.key();
        config.price_per_trace_lamports = params.price_per_trace_lamports;
        config.bump = ctx.bumps.payment_config;

        emit!(ConfigInitialized {
            authority: config.authority,
            mint: config.mint,
            treasury: config.treasury,
            price_per_trace_lamports: config.price_per_trace_lamports,
        });

        Ok(())
    }

    /// Create a payment session for x402 protocol
    /// 
    /// This implements the x402 HTTP 402 Payment Required protocol:
    /// 1. Client requests trace without payment
    /// 2. Server returns 402 with payment session details
    /// 3. Client creates payment session on-chain
    /// 4. Client submits payment transaction
    /// 5. Server verifies payment and returns trace
    pub fn create_payment_session(
        ctx: Context<CreatePaymentSession>,
        params: CreatePaymentSessionParams,
    ) -> Result<()> {
        let session = &mut ctx.accounts.payment_session;
        session.payer = ctx.accounts.payer.key();
        session.config = ctx.accounts.payment_config.key();
        session.trace_id = params.trace_id;
        session.amount_lamports = ctx.accounts.payment_config.price_per_trace_lamports;
        session.paid = false;
        session.refunded = false;
        session.created_at = Clock::get()?.unix_timestamp;
        session.bump = ctx.bumps.payment_session;

        emit!(PaymentSessionCreated {
            session: ctx.accounts.payment_session.key(),
            payer: session.payer,
            trace_id: session.trace_id,
            amount_lamports: session.amount_lamports,
        });

        Ok(())
    }

    /// Execute payment for a trace (x402 protocol step 4)
    pub fn pay_for_trace(ctx: Context<PayForTrace>) -> Result<()> {
        let session = &mut ctx.accounts.payment_session;

        require!(!session.paid, MicropaymentError::AlreadyPaid);
        require!(!session.refunded, MicropaymentError::AlreadyRefunded);

        let config = &ctx.accounts.payment_config;
        let amount = session.amount_lamports;

        // Transfer USDC (Token-2022) from payer to treasury
        let cpi_accounts = TransferChecked {
            from: ctx.accounts.payer_token_account.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.treasury_token_account.to_account_info(),
            authority: ctx.accounts.payer.to_account_info(),
        };

        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

        // Token-2022 requires decimals parameter
        let decimals = ctx.accounts.mint.decimals;
        token_2022::transfer_checked(cpi_ctx, amount, decimals)?;

        session.paid = true;
        session.paid_at = Some(Clock::get()?.unix_timestamp);

        emit!(PaymentExecuted {
            session: ctx.accounts.payment_session.key(),
            payer: session.payer,
            amount_lamports: amount,
            trace_id: session.trace_id,
        });

        Ok(())
    }

    /// Refund a payment (if service not delivered)
    pub fn refund_payment(ctx: Context<RefundPayment>) -> Result<()> {
        let session = &mut ctx.accounts.payment_session;

        require!(session.paid, MicropaymentError::NotPaid);
        require!(!session.refunded, MicropaymentError::AlreadyRefunded);

        let config = &ctx.accounts.payment_config;
        let amount = session.amount_lamports;

        // Transfer USDC back from treasury to payer
        let seeds = &[
            b"payment_config",
            config.authority.as_ref(),
            &[config.bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = TransferChecked {
            from: ctx.accounts.treasury_token_account.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.payer_token_account.to_account_info(),
            authority: ctx.accounts.payment_config.to_account_info(),
        };

        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);

        let decimals = ctx.accounts.mint.decimals;
        token_2022::transfer_checked(cpi_ctx, amount, decimals)?;

        session.refunded = true;
        session.refunded_at = Some(Clock::get()?.unix_timestamp);

        emit!(PaymentRefunded {
            session: ctx.accounts.payment_session.key(),
            payer: session.payer,
            amount_lamports: amount,
            trace_id: session.trace_id,
        });

        Ok(())
    }

    /// Update payment config (authority only)
    pub fn update_config(
        ctx: Context<UpdateConfig>,
        params: UpdateConfigParams,
    ) -> Result<()> {
        let config = &mut ctx.accounts.payment_config;

        if let Some(price) = params.price_per_trace_lamports {
            config.price_per_trace_lamports = price;
        }

        if let Some(treasury) = params.treasury {
            config.treasury = treasury;
        }

        emit!(ConfigUpdated {
            authority: config.authority,
            price_per_trace_lamports: config.price_per_trace_lamports,
            treasury: config.treasury,
        });

        Ok(())
    }
}

// ============================================================================
// State
// ============================================================================

#[account]
pub struct PaymentConfig {
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub treasury: Pubkey,
    pub price_per_trace_lamports: u64,
    pub bump: u8,
}

impl PaymentConfig {
    pub const SPACE: usize = 8 + 32 + 32 + 32 + 8 + 1;
}

#[account]
pub struct PaymentSession {
    pub payer: Pubkey,
    pub config: Pubkey,
    pub trace_id: [u8; 16],
    pub amount_lamports: u64,
    pub paid: bool,
    pub refunded: bool,
    pub created_at: i64,
    pub paid_at: Option<i64>,
    pub refunded_at: Option<i64>,
    pub bump: u8,
}

impl PaymentSession {
    pub const SPACE: usize = 8 + 32 + 32 + 16 + 8 + 1 + 1 + 8 + 9 + 9 + 1;
}

// ============================================================================
// Instructions
// ============================================================================

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializeConfigParams {
    pub authority: Pubkey,
    pub price_per_trace_lamports: u64,
}

#[derive(Accounts)]
#[instruction(params: InitializeConfigParams)]
pub struct InitializeConfig<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = PaymentConfig::SPACE,
        seeds = [b"payment_config", params.authority.as_ref()],
        bump
    )]
    pub payment_config: Account<'info, PaymentConfig>,

    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        constraint = treasury.mint == mint.key(),
        constraint = treasury.owner == payment_config.key()
    )]
    pub treasury: InterfaceAccount<'info, TokenAccount>,

    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct CreatePaymentSessionParams {
    pub trace_id: [u8; 16],
}

#[derive(Accounts)]
#[instruction(params: CreatePaymentSessionParams)]
pub struct CreatePaymentSession<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        seeds = [b"payment_config", payment_config.authority.as_ref()],
        bump = payment_config.bump
    )]
    pub payment_config: Account<'info, PaymentConfig>,

    #[account(
        init,
        payer = payer,
        space = PaymentSession::SPACE,
        seeds = [b"payment_session", payer.key().as_ref(), &params.trace_id],
        bump
    )]
    pub payment_session: Account<'info, PaymentSession>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PayForTrace<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"payment_session", payer.key().as_ref(), &payment_session.trace_id],
        bump = payment_session.bump,
        constraint = payment_session.payer == payer.key()
    )]
    pub payment_session: Account<'info, PaymentSession>,

    #[account(
        seeds = [b"payment_config", payment_config.authority.as_ref()],
        bump = payment_config.bump
    )]
    pub payment_config: Account<'info, PaymentConfig>,

    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        constraint = payer_token_account.owner == payer.key(),
        constraint = payer_token_account.mint == mint.key()
    )]
    pub payer_token_account: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        constraint = treasury_token_account.key() == payment_config.treasury,
        constraint = treasury_token_account.mint == mint.key()
    )]
    pub treasury_token_account: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct RefundPayment<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"payment_session", payment_session.payer.as_ref(), &payment_session.trace_id],
        bump = payment_session.bump
    )]
    pub payment_session: Account<'info, PaymentSession>,

    #[account(
        seeds = [b"payment_config", authority.key().as_ref()],
        bump = payment_config.bump,
        constraint = payment_config.authority == authority.key()
    )]
    pub payment_config: Account<'info, PaymentConfig>,

    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        constraint = payer_token_account.owner == payment_session.payer,
        constraint = payer_token_account.mint == mint.key()
    )]
    pub payer_token_account: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        constraint = treasury_token_account.key() == payment_config.treasury,
        constraint = treasury_token_account.mint == mint.key()
    )]
    pub treasury_token_account: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct UpdateConfigParams {
    pub price_per_trace_lamports: Option<u64>,
    pub treasury: Option<Pubkey>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"payment_config", authority.key().as_ref()],
        bump = payment_config.bump,
        constraint = payment_config.authority == authority.key()
    )]
    pub payment_config: Account<'info, PaymentConfig>,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct ConfigInitialized {
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub treasury: Pubkey,
    pub price_per_trace_lamports: u64,
}

#[event]
pub struct PaymentSessionCreated {
    pub session: Pubkey,
    pub payer: Pubkey,
    pub trace_id: [u8; 16],
    pub amount_lamports: u64,
}

#[event]
pub struct PaymentExecuted {
    pub session: Pubkey,
    pub payer: Pubkey,
    pub amount_lamports: u64,
    pub trace_id: [u8; 16],
}

#[event]
pub struct PaymentRefunded {
    pub session: Pubkey,
    pub payer: Pubkey,
    pub amount_lamports: u64,
    pub trace_id: [u8; 16],
}

#[event]
pub struct ConfigUpdated {
    pub authority: Pubkey,
    pub price_per_trace_lamports: u64,
    pub treasury: Pubkey,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum MicropaymentError {
    #[msg("Payment already executed")]
    AlreadyPaid,

    #[msg("Payment not yet executed")]
    NotPaid,

    #[msg("Payment already refunded")]
    AlreadyRefunded,

    #[msg("Invalid payment amount")]
    InvalidAmount,
}
