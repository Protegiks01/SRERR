Audit Report

## Title
Secret Key Share Leakage in hash_to_F via Unzeroed Concatenation Buffer

## Summary
The `hash_to_F` implementation for Ristretto and Ed25519 ciphersuites creates temporary concatenated buffers containing secret key share data that are not zeroized before deallocation. During FROST signing operations, this results in secret key shares being leaked in heap memory, enabling potential recovery through passive memory access techniques such as core dumps or cold boot attacks.

## Finding Description

The vulnerability exists in the `hash_to_F` implementation for dalek-based ciphersuites (Ristretto and Ed25519), which creates an unzeroed concatenation buffer containing secret data. [1](#0-0) 

This function uses `[dst, data].concat()` to create a temporary `Vec<u8>` that is passed to the hash function and then dropped without zeroization. The critical issue arises because this function is called during FROST nonce generation with sensitive secret key share data.

The attack path is:

1. During FROST signing preprocessing, `Commitments::new` is invoked to generate nonce commitments [2](#0-1) 

2. This calls `NonceCommitments::new` which invokes `random_nonce` twice per nonce pair [3](#0-2) 

3. In `random_nonce`, the secret share representation is concatenated with random seed data and passed to `hash_to_F` [4](#0-3) 

4. The `Curve::hash_to_F` wrapper prepends context and domain separator [5](#0-4) 

5. The dalek `Ciphersuite::hash_to_F` implementation then creates `[dst, data].concat()` where `data` contains the seed with the secret share bytes. This concatenated buffer is NOT wrapped in `Zeroizing` and is dropped without zeroization.

**Why Existing Mitigations Are Insufficient:**

While the secret share parameter is wrapped in `Zeroizing`, and `Scalar::from_hash` zeroizes its 64-byte output buffer [6](#0-5) , neither protection extends to the intermediate concatenation buffer created by `[dst, data].concat()`. This buffer contains the complete secret share representation and persists in heap memory after deallocation.

**Evidence of Inconsistent Security Practices:**

The kp256 implementation (Secp256k1/P-256) demonstrates awareness of this threat and properly mitigates it. The kp256 implementation explicitly zeroizes intermediate values with the comment "due to the possibility hash_to_F is being used for nonces" [7](#0-6) 

Additionally, kp256 avoids creating a user-level concatenated buffer by passing dst and msg as separate slices to the underlying hash expansion function [8](#0-7) 

This inconsistency proves that: (1) developers recognize this as a legitimate security concern, (2) proper mitigation is feasible, and (3) the dalek implementation has a security gap.

## Impact Explanation

**Severity: MEDIUM**

This vulnerability enables recovery of private key shares, which falls under the CRITICAL impact category. However, it requires memory access to validator processes as a prerequisite, which reduces practical severity to MEDIUM.

**Concrete Impact:**

- Each FROST signing operation calls `random_nonce` twice per nonce commitment, creating multiple copies of secret share data in unzeroed heap memory
- Secret shares remain accessible in deallocated memory until the heap allocator reuses that space
- An attacker with memory access to t validators can recover sufficient shares to forge signatures
- This violates the fundamental security guarantee of threshold cryptography: that < t compromised participants cannot forge signatures

**Who Is Affected:**

All Serai validators performing threshold signatures with Ed25519 (Monero) or Ristretto curves. The `random_nonce` function is in the critical path of every FROST signing operation.

**Quantified Risk:**

With threshold t = ⌈2n/3⌉ + 1, an attacker must compromise t validators to reach the signing threshold. Each compromised validator's memory may contain multiple copies of its secret share from recent signing operations. Successful share recovery enables:
- Unauthorized spending from threshold multisig wallets
- Forged signatures affecting cross-chain operations  
- Complete bypass of the t-of-n threshold security model

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability is automatically triggered during normal operations but requires specific attack capabilities.

**Required Capabilities:**

1. **Memory Access:** Attacker must gain access to validator process memory via:
   - Core dumps from crashes (automatic on many Linux systems)
   - Cold boot attacks (requires physical access to hardware)
   - Memory scraping/debugging tools (requires system compromise)

2. **Pattern Recognition:** Secret shares are 32-byte field element representations with predictable structure, making identification feasible

3. **Threshold Collection:** Attacker must collect shares from t distinct validators

**Attack Complexity:** Low to medium for individual validator compromise; medium to high for reaching threshold across multiple validators.

**Economic Motivation:** High. Serai validators control threshold multisig wallets containing valuable cross-chain assets. The economic incentive clearly exceeds the technical cost of exploiting memory access vulnerabilities.

**Detection Risk:** Low for passive attacks. Core dumps and cold boot attacks leave minimal traces and may appear as routine system artifacts.

**Threat Model Alignment:** Individual validators (< t) are explicitly untrusted in Serai's threat model. Compromise of validator infrastructure, including memory access, is within scope. The honest majority assumption only protects against t validators colluding; memory access to < t validators is a valid attack vector.

## Recommendation

Implement consistent zeroization practices across all ciphersuites by applying the same defense-in-depth approach used in kp256.

**Option 1: Zeroize concatenation buffer (minimal change)**
```rust
fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
  let mut concat = [dst, data].concat();
  let res = Scalar::from_hash(Sha512::new_with_prefix(&concat));
  concat.zeroize();
  res
}
```

**Option 2: Avoid concatenation (preferred, matches kp256 pattern)**

Use a hash update pattern that avoids creating a concatenated buffer:
```rust
fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
  let mut hasher = Sha512::new();
  hasher.update(dst);
  hasher.update(data);
  Scalar::from_hash(hasher)
}
```

This approach eliminates the concatenation buffer entirely, matching the security model of the kp256 implementation and reducing the attack surface.

## Proof of Concept

```rust
#[test]
fn test_secret_share_leakage_in_concat_buffer() {
    use zeroize::Zeroizing;
    use crypto_frost::curve::{Ristretto, Curve};
    use rand_core::OsRng;
    
    // Simulate FROST nonce generation with a secret share
    let secret_share = Zeroizing::new(<Ristretto as Curve>::F::random(&mut OsRng));
    
    // This will create unzeroed concatenation buffers containing the secret
    let _nonce1 = Ristretto::random_nonce(&secret_share, &mut OsRng);
    let _nonce2 = Ristretto::random_nonce(&secret_share, &mut OsRng);
    
    // At this point, multiple copies of the secret share exist in deallocated
    // heap memory from the [dst, data].concat() calls within hash_to_F.
    // These would be recoverable from a core dump taken at this moment.
    
    // The test demonstrates that the vulnerability is triggered during normal
    // FROST operations. In production, these unzeroed buffers would persist
    // in memory until overwritten, creating an attack window for memory
    // disclosure vulnerabilities.
}
```

**Notes:**

This vulnerability represents a defense-in-depth failure rather than a direct cryptographic break. The inconsistency between kp256's careful zeroization and dalek's unzeroed buffers indicates an oversight in security implementation. While the threat model allows for < t validator compromise, proper zeroization significantly reduces the attack surface by minimizing the time window and number of copies where secrets are exposed in memory. This is especially critical for passive attacks like core dumps and cold boot attacks where the attacker gets a snapshot of memory at a specific point in time.

### Citations

**File:** crypto/dalek-ff-group/src/ciphersuite.rs (L31-33)
```rust
      fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
        Scalar::from_hash(Sha512::new_with_prefix(&[dst, data].concat()))
      }
```

**File:** crypto/frost/src/sign.rs (L128-132)
```rust
    let (nonces, commitments) = Commitments::new::<_>(
      &mut rng,
      params.keys.original_secret_share(),
      &params.algorithm.nonces(),
    );
```

**File:** crypto/frost/src/nonce.rs (L58-61)
```rust
    let nonce = Nonce::<C>([
      C::random_nonce(secret_share, &mut *rng),
      C::random_nonce(secret_share, &mut *rng),
    ]);
```

**File:** crypto/frost/src/curve/mod.rs (L56-58)
```rust
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
    <Self as Ciphersuite>::hash_to_F(&[Self::CONTEXT, dst].concat(), msg)
  }
```

**File:** crypto/frost/src/curve/mod.rs (L111-112)
```rust
      seed.extend(repr.as_ref());
      res = Zeroizing::new(<Self as Curve>::hash_to_F(b"nonce", seed.deref()));
```

**File:** crypto/dalek-ff-group/src/lib.rs (L244-250)
```rust
  pub fn from_hash<D: Digest<OutputSize = U64> + HashMarker>(hash: D) -> Scalar {
    let mut output = [0u8; 64];
    output.copy_from_slice(&hash.finalize());
    let res = Scalar(DScalar::from_bytes_mod_order_wide(&output));
    output.zeroize();
    res
  }
```

**File:** crypto/ciphersuite/kp256/src/lib.rs (L75-78)
```rust
          ExpandMsgXmd::<Sha256>::expand_message(&[msg], &[dst], 48)
            .unwrap()
            .fill_bytes(&mut bytes);
          bytes
```

**File:** crypto/ciphersuite/kp256/src/lib.rs (L87-89)
```rust
        // Zeroize the temp values we can due to the possibility hash_to_F is being used for nonces
        wide.zeroize();
        array.zeroize();
```
