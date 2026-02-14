use arcis::*;

#[encrypted]
mod bio_auth_engine {
    use arcis::*;

    /// Biometric data structure
    /// Upgrade: Use [u64; 4] to simulate a more complex feature vector
    /// Real FaceID/TouchID extracts a set of feature points, not a single hash
    pub struct BioData {
        pub features: [u64; 4],
    }

    /// Authentication result
    pub struct AuthResult {
        pub match_score: u64,      // Number of matching feature segments (for debugging/analysis)
        pub is_authenticated: u64, // 1 for pass, 0 for reject
    }

    /// Core instruction: Fuzzy matching of biometric features
    #[instruction]
    pub fn verify_biometric(
        template_ctxt: Enc<Shared, BioData>, // Registered template stored on-chain
        attempt_ctxt: Enc<Shared, BioData>   // User's current login attempt
    ) -> Enc<Shared, AuthResult> {
        let template = template_ctxt.to_arcis();
        let attempt = attempt_ctxt.to_arcis();
        
        let mut score = 0u64;

        // Perform parallel feature comparison
        // We compare 4 feature segments. Due to lighting/angle effects on biometric data collection,
        // it is often not 100% identical. We need to calculate "similarity" rather than "equality."
        for i in 0..4 {
            let is_segment_match = template.features[i] == attempt.features[i];
            
            // Use Mux (Multiplexer) to accumulate the score
            score = if is_segment_match { score + 1 } else { score };
        }

        // Threshold determination logic
        // Set threshold: If at least 3 out of 4 segments match (75% similarity), authentication passes
        let passed = if score >= 3 { 
            1u64 
        } else { 
            0u64 
        };

        let result = AuthResult {
            match_score: score,
            is_authenticated: passed,
        };

        // Re-encrypt the result and return it to the requester
        // Note: The template owner and the attempt user are usually the same person,
        // so the result is returned to the owner (template_ctxt.owner)
        template_ctxt.owner.from_arcis(result)
    }
}