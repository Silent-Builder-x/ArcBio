use arcis::*;

#[encrypted]
mod bio_auth_engine {
    use arcis::*;

    pub struct BioData {
        pub feature_hash: u64, // 模拟提取后的生物特征哈希/向量
    }

    pub struct AuthResult {
        pub is_authenticated: u64, // 1 为通过, 0 为拒绝
    }

    #[instruction]
    pub fn verify_biometric(
        template_ctxt: Enc<Shared, BioData>,
        attempt_ctxt: Enc<Shared, BioData>
    ) -> Enc<Shared, AuthResult> {
        let template = template_ctxt.to_arcis();
        let attempt = attempt_ctxt.to_arcis();

        // 执行同态比对逻辑
        let is_match = attempt.feature_hash == template.feature_hash;

        // 使用 V4 规范的 if-else Mux 结构
        let auth_status = if is_match {
            1u64
        } else {
            0u64
        };

        let result = AuthResult {
            is_authenticated: auth_status,
        };

        template_ctxt.owner.from_arcis(result)
    }
}