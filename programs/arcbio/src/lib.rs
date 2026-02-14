use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

// Must match the definition when uploading circuits via Arcium CLI
const COMP_DEF_OFFSET_BIO: u32 = comp_def_offset("verify_biometric");

declare_id!("4cdJunzkC36NG7o8ou9rgpkdQtw4bh4CFGW5VfbPLwUM");

#[arcium_program]
pub mod arcbio {
    use super::*;

    pub fn init_bio_config(ctx: Context<InitBioCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    /// [New] Register/Enroll biometric data
    /// Users extract features locally, encrypt them, and call this instruction to store them on-chain
    pub fn register_biometrics(
        ctx: Context<RegisterBio>,
        encrypted_features: [[u8; 32]; 4], // Accepts 4 encrypted shards
    ) -> Result<()> {
        let profile = &mut ctx.accounts.bio_profile;
        profile.owner = ctx.accounts.owner.key();
        profile.encrypted_template = encrypted_features;
        profile.bump = ctx.bumps.bio_profile;
        
        msg!("Biometric Template Registered for User: {}", profile.owner);
        Ok(())
    }

    /// Request login authentication
    /// Compare: stored template on-chain vs current attempt data
    pub fn request_authentication(
        ctx: Context<RequestBioAuth>,
        computation_offset: u64,
        attempt_encrypted: [[u8; 32]; 4], // Current login attempt (encrypted)
        pubkey: [u8; 32],                 // Result re-encryption public key
        nonce: u128,
    ) -> Result<()> {
        let accounts = &mut ctx.accounts.computation;
        accounts.sign_pda_account.bump = ctx.bumps.computation.sign_pda_account;
        
        // Build MPC parameters
        // The order must strictly correspond to circuit inputs: fn verify_biometric(template, attempt)
        let mut builder = ArgBuilder::new()
            .x25519_pubkey(pubkey)
            .plaintext_u128(nonce);

        // Parameter 1: Template (read from the on-chain Profile account)
        for shard in &ctx.accounts.bio_profile.encrypted_template {
            builder = builder.encrypted_u64(*shard);
        }

        // Parameter 2: Attempt (passed from instruction arguments)
        for shard in &attempt_encrypted {
            builder = builder.encrypted_u64(*shard);
        }

        queue_computation(
            accounts,
            computation_offset,
            builder.build(),
            vec![VerifyBiometricCallback::callback_ix(
                computation_offset,
                &accounts.mxe_account,
                &[]
            )?],
            1, // Requires 1 execution node
            0,
        )?;
        
        msg!("Biometric Auth Computation Queued via Arcium MXE.");
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "verify_biometric")]
    pub fn verify_biometric_callback(
        ctx: Context<VerifyBiometricCallback>,
        output: SignedComputationOutputs<VerifyBiometricOutput>,
    ) -> Result<()> {
        // Verify computation result signature
        let o = match output.verify_output(&ctx.accounts.cluster_account, &ctx.accounts.computation_account) {
            // Correction: Struct name must be VerifyBiometricOutput
            Ok(VerifyBiometricOutput { field_0 }) => field_0, 
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        // Parse results
        // Arcis returns: { match_score: u64, is_authenticated: u64 }
        let score_bytes: [u8; 8] = o.ciphertexts[0][0..8].try_into().unwrap();
        let status_bytes: [u8; 8] = o.ciphertexts[1][0..8].try_into().unwrap();

        let match_score = u64::from_le_bytes(score_bytes);
        let is_authenticated = u64::from_le_bytes(status_bytes) == 1;

        if is_authenticated {
            msg!("✅ ACCESS GRANTED: Biometric Match Confirmed (Score: {}/4)", match_score);
        } else {
            msg!("⛔ ACCESS DENIED: Biometric Mismatch (Score: {}/4)", match_score);
        }

        emit!(AuthEvent {
            user: ctx.accounts.computation_account.key(), 
            success: is_authenticated,
            score: match_score,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }
}

// --- Accounts & Validation ---

#[derive(Accounts)]
pub struct RegisterBio<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        init,
        payer = owner,
        // Space: Disc(8) + Pubkey(32) + 4x32 Encrypted Data(128) + Bump(1)
        space = 8 + 32 + 128 + 1,
        seeds = [b"bio_auth", owner.key().as_ref()],
        bump
    )]
    pub bio_profile: Account<'info, BiometricProfile>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct BiometricProfile {
    pub owner: Pubkey,
    pub encrypted_template: [[u8; 32]; 4], // Stores registered template
    pub bump: u8,
}

// Wrap basic computation accounts to reduce repetitive code
#[queue_computation_accounts("verify_biometric", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct RequestBioAuthBase<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init_if_needed, space = 9, payer = payer, seeds = [&SIGN_PDA_SEED], bump, address = derive_sign_pda!())]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>, // Box to avoid stack overflow
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

#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct RequestBioAuth<'info> {
    pub computation: RequestBioAuthBase<'info>,
    
    // A registered Bio Profile must be passed in for comparison
    #[account(
        seeds = [b"bio_auth", bio_profile.owner.as_ref()],
        bump = bio_profile.bump,
    )]
    pub bio_profile: Account<'info, BiometricProfile>,
}

#[callback_accounts("verify_biometric")]
#[derive(Accounts)]
pub struct VerifyBiometricCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_BIO))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
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

#[event]
pub struct AuthEvent {
    pub user: Pubkey,
    pub success: bool,
    pub score: u64,
    pub timestamp: i64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Aborted")] AbortedComputation,
    #[msg("No Cluster")] ClusterNotSet,
}