use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

const COMP_DEF_OFFSET_BIO: u32 = comp_def_offset("verify_biometric");

declare_id!("Ge5bHtRma92N1MYYDmC2wicJ4URfCyNJEp4QR39rQzMx");

#[arcium_program]
pub mod arcbio {
    use super::*;

    pub fn init_bio_config(ctx: Context<InitBioCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    pub fn request_authentication(
        ctx: Context<RequestBioAuth>,
        computation_offset: u64,
        template_ctxt: [u8; 32],
        attempt_ctxt: [u8; 32],
        pubkey: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        
        let args = ArgBuilder::new()
            .x25519_pubkey(pubkey)
            .plaintext_u128(nonce)
            .encrypted_u64(template_ctxt)
            .encrypted_u64(attempt_ctxt)
            .build();

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![VerifyBiometricCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[]
            )?],
            1,
            0,
        )?;
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "verify_biometric")]
    pub fn verify_biometric_callback(
        ctx: Context<VerifyBiometricCallback>,
        output: SignedComputationOutputs<VerifyBiometricOutput>,
    ) -> Result<()> {
        let _res = match output.verify_output(&ctx.accounts.cluster_account, &ctx.accounts.computation_account) {
            Ok(result) => result,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };
        msg!("Confidential Biometric Authentication Verified via MXE.");
        Ok(())
    }
}

#[queue_computation_accounts("verify_biometric", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct RequestBioAuth<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init_if_needed, space = 9, payer = payer, seeds = [&SIGN_PDA_SEED], bump, address = derive_sign_pda!())]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: Arcium Internal Mempool
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: Arcium Execution Pool
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: Computation context tracking
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_BIO))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("verify_biometric")]
#[derive(Accounts)]
pub struct VerifyBiometricCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_BIO))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: Validated result from MXE cluster
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: Solana Instruction Sysvar
    pub instructions_sysvar: AccountInfo<'info>,
}

#[init_computation_definition_accounts("verify_biometric", payer)]
#[derive(Accounts)]
pub struct InitBioCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: New definition for bio-auth circuit
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: LUT for network routing
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: Official LUT Program
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Aborted")] AbortedComputation,
    #[msg("No Cluster")] ClusterNotSet,
}
