use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

// 必须与 Arcium CLI 上传电路时的定义一致
const COMP_DEF_OFFSET_BIO: u32 = comp_def_offset("verify_biometric");

declare_id!("FHELxPeKoWRLbopi2ZXqfYFd1rfcL7Zcj9moQKXMbuni");

#[arcium_program]
pub mod arcbio {
    use super::*;

    pub fn init_bio_config(ctx: Context<InitBioCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    /// [新增] 注册/录入生物特征
    /// 用户在本地提取特征并加密后，调用此指令存储到链上
    pub fn register_biometrics(
        ctx: Context<RegisterBio>,
        encrypted_features: [[u8; 32]; 4], // 接收 4 个加密分片
    ) -> Result<()> {
        let profile = &mut ctx.accounts.bio_profile;
        profile.owner = ctx.accounts.owner.key();
        profile.encrypted_template = encrypted_features;
        profile.bump = ctx.bumps.bio_profile;
        
        msg!("Biometric Template Registered for User: {}", profile.owner);
        Ok(())
    }

    /// 请求登录验证
    /// 对比：链上存储的模版 vs 当前传入的尝试数据
    pub fn request_authentication(
        ctx: Context<RequestBioAuth>,
        computation_offset: u64,
        attempt_encrypted: [[u8; 32]; 4], // 当前的登录尝试（加密后）
        pubkey: [u8; 32],                 // 结果重加密公钥
        nonce: u128,
    ) -> Result<()> {
        let accounts = &mut ctx.accounts.computation;
        accounts.sign_pda_account.bump = ctx.bumps.computation.sign_pda_account;
        
        // 构建 MPC 参数
        // 顺序必须严格对应电路输入: fn verify_biometric(template, attempt)
        let mut builder = ArgBuilder::new()
            .x25519_pubkey(pubkey)
            .plaintext_u128(nonce);

        // 参数 1: Template (从链上 Profile 账户读取)
        for shard in &ctx.accounts.bio_profile.encrypted_template {
            builder = builder.encrypted_u64(*shard);
        }

        // 参数 2: Attempt (从指令参数传入)
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
            1, // 需要 1 个执行节点
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
        // 验证计算结果签名
        let o = match output.verify_output(&ctx.accounts.cluster_account, &ctx.accounts.computation_account) {
            // 修正：结构体名必须是 VerifyBiometricOutput
            Ok(VerifyBiometricOutput { field_0 }) => field_0, 
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        // 解析结果
        // Arcis 返回: { match_score: u64, is_authenticated: u64 }
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
    pub encrypted_template: [[u8; 32]; 4], // 存储注册模版
    pub bump: u8,
}

// 包装基础计算账户，减少重复代码
#[queue_computation_accounts("verify_biometric", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct RequestBioAuthBase<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init_if_needed, space = 9, payer = payer, seeds = [&SIGN_PDA_SEED], bump, address = derive_sign_pda!())]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>, // Box 避免栈溢出
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
    
    // 必须传入已注册的 Bio Profile 才能进行比对
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