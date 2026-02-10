# ArcBio: Vendor-Agnostic Confidential Biometric Authentication

## 🧬 Overview

**ArcBio** is a privacy-preserving identity protocol built on **Arcium** and **Solana**.

Current biometric systems (FaceID, TouchID) are either locked within specific hardware vendors or risk leaking sensitive biological metadata to centralized servers. **ArcBio** decouples biometric identity from hardware by utilizing **Fully Homomorphic Encryption (FHE)**. Biometric templates are secret-shared across the Arcium network, and matching is performed entirely within the ciphertext space.

Apps receive only a "match/no-match" signal, ensuring the user's raw biological features remain mathematically unobservable to any observer or node operator.

## 🚀 Live Deployment Status (Devnet)

The protocol is fully operational and verified on the Arcium Devnet.

- **MXE Address:** `2yGWJCB5yMA7wTm31T8CX5xTVX7ESp9YpunR68C4sWWw`
- **MXE Program ID:** `FHELxPeKoWRLbopi2ZXqfYFd1rfcL7Zcj9moQKXMbuni`
- **Computation Definition:** `GxzuhC3uXPJcCdykYehhzZuzxs9m12JvHipcWuf3Ntjg`
- **Status:** `Active`

## 🧠 Core Innovation: "Silent Biometrics"

ArcBio implements a universal authentication primitive:

- **Encrypted Enrollment:** Biometric feature vectors are encrypted locally using x25519 before being committed as state.
- **Homomorphic Equality Test:** The Arcis circuit executes a constant-time equality check between the "Attempt" and "Template" ciphertexts using optimized multiplexers.
- **Zero-Trust Settlement:** Final verification is finalized via Arcium's threshold signature process and committed to the Solana ledger via verified callbacks.

## 🛠 Build & Implementation

```
# Compile Arcis circuits and Anchor program
arcium build

# Deploy to Cluster 456
arcium deploy --cluster-offset 456 --recovery-set-size 4 --keypair-path ~/.config/solana/id.json -u d

```

## 📄 Technical Specification

- **Circuit:** `verify_biometric` (Arcis-FHE)
- **Security:** Supported by Arcium Multi-Party Execution & Recovery Set (Size 4).
- **Audit Compliance:** Built following **PhD Internal V4** standards with explicit `/// CHECK:` safety comments.