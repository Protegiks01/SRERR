### Title
Schnorr Signature Verification Accepts Identity Element as Public Key, Enabling DKG Proof-of-Possession Bypass

### Summary
The `SchnorrSignature::verify()` function does not validate that the `public_key` parameter is not the identity element, allowing attackers to forge signatures for the identity key. This vulnerability is exploitable during DKG proof-of-possession verification, where a malicious participant can submit commitments with the identity element and a forged PoK signature, bypassing the critical proof-of-possession requirement and violating DKG integrity.

### Finding Description

**Exact Code Location:** [1](#0-0) 

The `verify()` function evaluates the Schnorr verification equation R + c*A - s*G = 0 without checking if the public key A is the identity element. [2](#0-1) 

The `batch_statements()` method constructs the verification equation terms including `(challenge, public_key)`. When `public_key` is the identity element O, the term `challenge * O` equals O (identity), causing the equation to degenerate to R - s*G = 0, or R = s*G.

**Root Cause:**
The verification equation mathematically breaks down when the public key is the identity element. For a valid signature (R, s) with challenge c and public key A, the equation s*G = R + c*A must hold. When A = O (identity):
- s*G = R + c*O
- s*G = R + O  
- s*G = R

An attacker can forge a "signature" by choosing any scalar s and setting R = s*G.

**Why Existing Mitigations Fail:**

The FROST library provides `Curve::read_G()` which validates against identity: [3](#0-2) 

However, this protection does not apply during DKG commitment verification. When commitments are deserialized, they use `Ciphersuite::read_G()`: [4](#0-3) [5](#0-4) 

The `Ciphersuite::read_G()` function only validates canonicity, not that the point is non-identity.

During DKG proof-of-possession verification, the vulnerable `verify()` path is reached: [6](#0-5) 

The `batch_verify()` call uses `msg.commitments[0]` (the first commitment, representing the public key) without validating it is not identity.

### Impact Explanation

**Specific Harm:**
A malicious validator participating in DKG can submit commitments where the first commitment (constant term) is the identity element, paired with a forged proof-of-possession signature. This bypasses the fundamental security property that participants must prove knowledge of their secret polynomial coefficients.

**Who Is Affected:**
All validators participating in a DKG session with a malicious participant. The compromised DKG would produce threshold keys that do not meet the security requirements.

**Severity Justification:**
This violates Critical Invariant #2: "DKG integrity: shares and commitments are validated; encrypted shares are bound to proofs-of-possession." The proof-of-possession is specifically designed to prevent rogue-key attacks and ensure each participant knows their secret. Bypassing this check undermines the security foundation of the entire threshold signature scheme. This qualifies as HIGH severity under the protocol scope: "Incorrect/incomplete cryptographic formulae within a verifier's callstack."

### Likelihood Explanation

**Required Attacker Capabilities:**
- Must be a registered validator participating in DKG
- Can construct and broadcast malicious commitment messages
- Requires basic knowledge of elliptic curve operations

**Attack Complexity:**
Low. The attack requires:
1. Setting commitments[0] to the identity element (a single group element)
2. Choosing an arbitrary scalar s
3. Computing R = s*G (single scalar multiplication)
4. Sending the forged commitment with signature (R, s)

**Economic Feasibility:**
Highly feasible. A malicious validator already has the capability to participate in DKG. The computational cost is negligible (single scalar multiplication).

**Detection Risk:**
Low detection risk during the attack. The forged PoK passes cryptographic verification. However, the resulting corrupted DKG shares would likely cause detectable failures during subsequent threshold signing operations.

### Recommendation

**Primary Fix:**
Add identity element validation in the `verify()` function before performing the verification equation check:

```rust
pub fn verify(&self, public_key: C::G, challenge: C::F) -> bool {
  // Reject identity element as public key
  if bool::from(public_key.is_identity()) {
    return false;
  }
  multiexp_vartime(&self.batch_statements(public_key, challenge)).is_identity().into()
}
```

**Alternative Mitigation:**
Add explicit validation in DKG commitment verification:

```rust
// In crypto/dkg/pedpop/src/lib.rs, verify_r1 function
for commitment in &msg.commitments {
  if bool::from(commitment.is_identity()) {
    Err(PedPoPError::InvalidCommitments(l))?;
  }
}
```

**Testing Recommendations:**
1. Add unit test attempting to verify a signature with identity public key
2. Add DKG integration test where a participant submits identity commitments
3. Verify that both mitigations correctly reject identity elements
4. Ensure no performance regression in the hot verification path

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup**: Malicious participant M joins DKG with parameters (t, n)

2. **Generate Forged Commitments**:
   - Set `commitments[0] = Identity` (O)
   - For i = 1 to t-1: generate normal commitments (or also identity)
   
3. **Forge Proof-of-Possession**:
   - Choose arbitrary scalar `s ← F` (e.g., s = 1)
   - Compute `R = s * G` where G is the generator
   - The PoK signature is `(R, s)`

4. **Compute Challenge**:
   - `c = challenge(context, participant_id, R, cached_commitments_msg)`
   - This is the Fiat-Shamir challenge binding to the context

5. **Verification Equation Check** (performed by honest participants):
   - They compute: `R + c*commitments[0] - s*G`
   - Since `commitments[0] = O`: `R + c*O - s*G = R - s*G`
   - Since `R = s*G`: `s*G - s*G = O` ✓ (verification passes!)

6. **Result**: Malicious commitments are accepted, violating proof-of-possession

**Expected vs Actual Behavior:**
- **Expected**: PoK verification should reject commitments where the participant doesn't prove knowledge of the secret coefficient
- **Actual**: Forged signatures verify successfully when the public key is identity, allowing bypass of the PoK requirement

### Citations

**File:** crypto/schnorr/src/lib.rs (L88-100)
```rust
  pub fn batch_statements(&self, public_key: C::G, challenge: C::F) -> [(C::F, C::G); 3] {
    // s = r + ca
    // sG == R + cA
    // R + cA - sG == 0
    [
      // R
      (C::F::ONE, self.R),
      // cA
      (challenge, public_key),
      // -sG
      (-self.s, C::generator()),
    ]
  }
```

**File:** crypto/schnorr/src/lib.rs (L108-110)
```rust
  pub fn verify(&self, public_key: C::G, challenge: C::F) -> bool {
    multiexp_vartime(&self.batch_statements(public_key, challenge)).is_identity().into()
  }
```

**File:** crypto/frost/src/curve/mod.rs (L123-131)
```rust
  /// Read a point from a reader, rejecting identity.
  #[allow(non_snake_case)]
  fn read_G<R: Read>(reader: &mut R) -> io::Result<Self::G> {
    let res = <Self as Ciphersuite>::read_G(reader)?;
    if res.is_identity().into() {
      Err(io::Error::other("identity point"))?;
    }
    Ok(res)
  }
```

**File:** crypto/dkg/pedpop/src/lib.rs (L118-120)
```rust
      let point = C::read_G(&mut buf.as_ref())?;
      cached_msg.extend(buf.as_ref());
      Ok(point)
```

**File:** crypto/dkg/pedpop/src/lib.rs (L323-329)
```rust
      msg.sig.batch_verify(
        rng,
        &mut batch,
        l,
        msg.commitments[0],
        challenge::<C>(self.context, l, msg.sig.R.to_bytes().as_ref(), &msg.cached_msg),
      );
```

**File:** crypto/ciphersuite/src/lib.rs (L85-101)
```rust
  /// Read a canonical point from something implementing std::io::Read.
  ///
  /// The provided implementation is safe so long as `GroupEncoding::to_bytes` always returns a
  /// canonical serialization.
  #[cfg(any(feature = "alloc", feature = "std"))]
  #[allow(non_snake_case)]
  fn read_G<R: Read>(reader: &mut R) -> io::Result<Self::G> {
    let mut encoding = <Self::G as GroupEncoding>::Repr::default();
    reader.read_exact(encoding.as_mut())?;

    let point = Option::<Self::G>::from(Self::G::from_bytes(&encoding))
      .ok_or_else(|| io::Error::other("invalid point"))?;
    if point.to_bytes().as_ref() != encoding.as_ref() {
      Err(io::Error::other("non-canonical point"))?;
    }
    Ok(point)
  }
```
