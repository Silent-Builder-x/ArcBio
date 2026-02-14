# ArcBio: Vendor-Agnostic Confidential Biometric Authentication 👁️

## 🧬 Overview

**ArcBio** is a privacy-preserving identity protocol built on **Arcium** and **Solana**.

Current biometric systems (FaceID, TouchID) are either locked within specific hardware vendors or risk leaking sensitive biological metadata to centralized servers. **ArcBio** decouples biometric identity from hardware by utilizing **MPC**. Biometric templates are secret-shared across the Arcium network, and matching is performed entirely within the ciphertext space.

Apps receive only a "match/no-match" signal, ensuring the user's raw biological features remain mathematically unobservable to any observer or node operator.

## 🚀 Live Deployment Status (Devnet v0.8.3)

The protocol is fully operational and verified on the Arcium Devnet.

### 🖥️ Interactive Demo

[Launch ArcBio Terminal](https://silent-builder-x.github.io/ArcBio/)

## 🧠 Core Innovation: "Silent Biometrics"

ArcBio implements a universal authentication primitive:

1. **Encrypted Enrollment:** Biometric feature vectors are encrypted locally using x25519 before being committed as state.
2. **Homomorphic Equality Test:** The Arcis circuit executes a constant-time equality check between the "Attempt" and "Template" ciphertexts using optimized multiplexers.
3. **Zero-Trust Settlement:** Final verification is finalized via Arcium's threshold signature process and committed to the Solana ledger via verified callbacks.

## 🛠 Architecture

```
graph LR
    A[User Device] -- 1. Encrypt Bio-Vector --> B(Solana Program)
    B -- 2. Queue Auth Request --> C{Arcium MXE Cluster}
    C -- 3. Homomorphic Match --> C
    C -- 4. Generate Proof --> B
    B -- 5. Emit Auth Token --> A

```

## ⚙️ Build & Implementation

### Prerequisites

- Arcium CLI `0.8.3`

### 1. Build Circuit

```
# Compile Arcis circuits and Anchor program
arcium build

```

### 2. Deploy to Cluster

```
# Deploy to Cluster 456
arcium deploy --cluster-offset 456 --recovery-set-size 4 --keypair-path ~/.config/solana/id.json -u d

```

## 📄 Technical Specification

- **Circuit:** `verify_biometric` (Arcis)
- **Security:** Supported by Arcium Multi-Party Execution & Recovery Set (Size 4).
- **Audit Compliance:** Built following **PhD Internal V4** standards with explicit `/// CHECK:` safety comments.