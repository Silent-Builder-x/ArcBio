use arcis::*;

#[encrypted]
mod bio_auth_engine {
    use arcis::*;

    /// 生物特征数据结构
    /// 升级：使用 [u64; 4] 模拟更复杂的生物特征向量（Feature Vector）
    /// 真实的 FaceID/TouchID 提取的是一组特征点，而非单一哈希
    pub struct BioData {
        pub features: [u64; 4],
    }

    /// 验证结果
    pub struct AuthResult {
        pub match_score: u64,      // 匹配的特征片段数量 (用于调试/分析)
        pub is_authenticated: u64, // 1 为通过, 0 为拒绝
    }

    /// 核心指令：生物特征模糊匹配 (Fuzzy Matching)
    #[instruction]
    pub fn verify_biometric(
        template_ctxt: Enc<Shared, BioData>, // 链上存储的注册模版
        attempt_ctxt: Enc<Shared, BioData>   // 用户当前的登录尝试
    ) -> Enc<Shared, AuthResult> {
        let template = template_ctxt.to_arcis();
        let attempt = attempt_ctxt.to_arcis();
        
        let mut score = 0u64;

        // 执行并行特征比对
        // 我们比较 4 个特征片段。因为生物数据采集受光线/角度影响，
        // 往往不会 100% 一致。我们需要计算“相似度”而非“全等性”。
        for i in 0..4 {
            let is_segment_match = template.features[i] == attempt.features[i];
            
            // 使用 Mux (Multiplexer) 累加分数
            score = if is_segment_match { score + 1 } else { score };
        }

        // 阈值判定逻辑
        // 设定阈值：如果 4 个片段中至少有 3 个匹配 (75% 相似度)，则认证通过
        let passed = if score >= 3 { 
            1u64 
        } else { 
            0u64 
        };

        let result = AuthResult {
            match_score: score,
            is_authenticated: passed,
        };

        // 将结果重新加密并返回给请求者
        // 注意：模版拥有者和尝试者通常是同一人，所以这里返回给 owner (template_ctxt.owner)
        template_ctxt.owner.from_arcis(result)
    }
}