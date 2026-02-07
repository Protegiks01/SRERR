# Audit Report

## Title
Identity Point Acceptance in DKG Commitments Enables Threshold Security Degradation

## Summary
The PedPoP DKG protocol uses `Ciphersuite::read_G()` for commitment deserialization, which accepts identity points as valid group elements. A malicious validator can exploit this by submitting commitments computed from a zero polynomial (f(x) = 0), producing identity commitments with mathematically valid Schnorr proofs of possession. This reduces the effective number of contributing participants, degrading the t-of-n threshold security to (t-k)-of-(n-k), where k malicious validators submit identity commitments.

## Finding Description

**Root Cause Analysis:**

The vulnerability stems from the different validation levels between two `read_G()` implementations:

1. **Ciphersuite::read_G()** [1](#0-0)  validates canonical encoding but does NOT reject identity points.

2. **Curve::read_G()** [2](#0-1)  explicitly rejects identity points after calling the Ciphersuite variant.

The PedPoP DKG protocol uses the Ciphersuite variant: [3](#0-2) 

**Exploitation Mechanism:**

A malicious validator can:

1. Generate a polynomial with all zero coefficients: f_i(x) = 0 (bypassing the honest `random_nonzero_F` used at [4](#0-3) )

2. Compute identity commitments: C_{i,j} = g^0 = I for all j

3. Create a valid Schnorr proof of possession with secret=0. The verification equation [5](#0-4)  becomes:
   - R + c*I - s*G = R + I - r*G = R - r*G = I (identity)
   - This verifies correctly because s = c*0 + r = r

4. The commitment verification at [6](#0-5)  batch-verifies these proofs without detecting identity commitments.

5. Send zero shares to other participants (valid field elements passing [7](#0-6) )

6. Share verification at [8](#0-7)  using [9](#0-8)  evaluates to: I + I + ... - 0*G = I (passes)

7. During aggregation [10](#0-9) , identity commitments contribute nothing to the stripe sums.

8. ThresholdKeys creation [11](#0-10)  computes the group key at [12](#0-11)  where identity verification shares contribute nothing.

**Security Guarantee Violation:**

The protocol guarantees that t-of-n participants are required to reconstruct the secret. With k malicious validators submitting identity commitments:
- Effective contributing participants: n-k
- The k malicious validators know their shares are zero (no entropy)
- An adversary controlling k malicious + (t-k) compromised honest validators can reconstruct
- **Actual threshold degraded to: t-k honest participants instead of t**

## Impact Explanation

**Severity: Critical**

This vulnerability matches the Critical category: "Unintended recovery of private spend keys or key shares."

**Concrete Impact:**
In a realistic Serai deployment (e.g., t=5, n=7):
- 2 malicious validators submit identity commitments
- Adversary compromises 3 honest validators  
- Total shares: 5 (meets threshold)
- Honest compromises: only 3 (violates security assumption requiring 5)
- **Result**: Group secret reconstructable with 40% fewer honest compromises

**Affected Systems:**
All Serai threshold wallets holding external assets (BTC, ETH, XMR) become vulnerable. The fundamental security model—requiring t compromised honest validators—is bypassed, enabling unauthorized spending with (t-k) compromises.

## Likelihood Explanation

**Attacker Profile:**
- Must be a validator (public role, requires stake)
- Uses only standard validator capabilities
- No cryptographic breaks required

**Attack Complexity: Low**
1. Locally construct zero polynomial (undetectable)
2. Submit identity commitments (pass all validation)
3. Provide valid Schnorr PoK (mathematically correct)
4. Send zero shares (valid field elements)

**Economic Feasibility: High**
- Cost: Validator stake/bond (existing requirement)
- Benefit: Reduced attack surface for compromising threshold wallet
- ROI: Extremely favorable for high-value cross-chain assets

**Detection Difficulty: High**
Identity points are valid group elements. Without explicit checks, they are indistinguishable from legitimate commitments at the protocol level. The Schnorr proof verifies correctly.

## Recommendation

Add explicit identity point rejection in PedPoP commitment validation:

```rust
// In crypto/dkg/pedpop/src/lib.rs, Commitments::read
#[allow(non_snake_case)]
let mut read_G = || -> io::Result<C::G> {
  let mut buf = <C::G as GroupEncoding>::Repr::default();
  reader.read_exact(buf.as_mut())?;
  let point = C::read_G(&mut buf.as_ref())?;
  
  // Add identity check
  if point.is_identity().into() {
    return Err(io::Error::other("identity point in commitment"));
  }
  
  cached_msg.extend(buf.as_ref());
  Ok(point)
};
```

Alternatively, create a stricter `read_G_non_identity()` method in the Ciphersuite trait and use it throughout DKG operations where identity must be rejected.

## Proof of Concept

```rust
#[test]
fn test_identity_commitment_attack() {
  use ciphersuite::{Ciphersuite, group::ff::Field};
  
  // Malicious validator creates zero polynomial
  let zero_coeff = C::F::ZERO;
  let identity_commitment = C::generator() * zero_coeff;
  assert!(identity_commitment.is_identity().into());
  
  // Serialize and deserialize through Ciphersuite::read_G
  let mut buf = identity_commitment.to_bytes();
  let deserialized = C::read_G(&mut buf.as_ref()).unwrap();
  
  // Identity passes validation (vulnerability)
  assert!(deserialized.is_identity().into());
  
  // Schnorr PoK with secret=0 verifies
  let nonce = C::random_nonzero_F(&mut rng);
  let R = C::generator() * nonce;
  let challenge = C::hash_to_F(b"test", R.to_bytes().as_ref());
  let s = nonce; // c * 0 + nonce = nonce
  
  // Verification: R + c*I - s*G = I (passes)
  let sig = SchnorrSignature { R, s };
  assert!(sig.verify(identity_commitment, challenge));
}
```

### Citations

**File:** crypto/ciphersuite/src/lib.rs (L91-101)
```rust
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

**File:** crypto/frost/src/curve/mod.rs (L125-131)
```rust
  fn read_G<R: Read>(reader: &mut R) -> io::Result<Self::G> {
    let res = <Self as Ciphersuite>::read_G(reader)?;
    if res.is_identity().into() {
      Err(io::Error::other("identity point"))?;
    }
    Ok(res)
  }
```

**File:** crypto/dkg/pedpop/src/lib.rs (L115-121)
```rust
    let mut read_G = || -> io::Result<C::G> {
      let mut buf = <C::G as GroupEncoding>::Repr::default();
      reader.read_exact(buf.as_mut())?;
      let point = C::read_G(&mut buf.as_ref())?;
      cached_msg.extend(buf.as_ref());
      Ok(point)
    };
```

**File:** crypto/dkg/pedpop/src/lib.rs (L167-167)
```rust
      coefficients.push(Zeroizing::new(C::random_nonzero_F(&mut *rng)));
```

**File:** crypto/dkg/pedpop/src/lib.rs (L323-334)
```rust
      msg.sig.batch_verify(
        rng,
        &mut batch,
        l,
        msg.commitments[0],
        challenge::<C>(self.context, l, msg.sig.R.to_bytes().as_ref(), &msg.cached_msg),
      );

      commitments.insert(l, msg.commitments.drain(..).collect::<Vec<_>>());
    }

    batch.verify_vartime_with_vartime_blame().map_err(PedPoPError::InvalidCommitments)?;
```

**File:** crypto/dkg/pedpop/src/lib.rs (L430-449)
```rust
fn share_verification_statements<C: Ciphersuite>(
  target: Participant,
  commitments: &[C::G],
  mut share: Zeroizing<C::F>,
) -> Vec<(C::F, C::G)> {
  // This can be insecurely linearized from n * t to just n using the below sums for a given
  // stripe. Doing so uses naive addition which is subject to malleability. The only way to
  // ensure that malleability isn't present is to use this n * t algorithm, which runs
  // per sender and not as an aggregate of all senders, which also enables blame
  let mut values = exponential::<C>(target, commitments);

  // Perform the share multiplication outside of the multiexp to minimize stack copying
  // While the multiexp BatchVerifier does zeroize its flattened multiexp, and itself, it still
  // converts whatever we give to an iterator and then builds a Vec internally, welcoming copies
  let neg_share_pub = C::generator() * -*share;
  share.zeroize();
  values.push((C::F::ONE, neg_share_pub));

  values
}
```

**File:** crypto/dkg/pedpop/src/lib.rs (L479-482)
```rust
      let share =
        Zeroizing::new(Option::<C::F>::from(C::F::from_repr(share_bytes.0)).ok_or_else(|| {
          PedPoPError::InvalidShare { participant: l, blame: Some(blame.clone()) }
        })?);
```

**File:** crypto/dkg/pedpop/src/lib.rs (L490-490)
```rust
        share_verification_statements::<C>(self.params.i(), &self.commitments[&l], share),
```

**File:** crypto/dkg/pedpop/src/lib.rs (L505-508)
```rust
    let mut stripes = Vec::with_capacity(usize::from(self.params.t()));
    for t in 0 .. usize::from(self.params.t()) {
      stripes.push(self.commitments.values().map(|commitments| commitments[t]).sum());
    }
```

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

**File:** crypto/dkg/src/lib.rs (L349-391)
```rust
  pub fn new(
    params: ThresholdParams,
    interpolation: Interpolation<C::F>,
    secret_share: Zeroizing<C::F>,
    verification_shares: HashMap<Participant, C::G>,
  ) -> Result<ThresholdKeys<C>, DkgError> {
    if verification_shares.len() != usize::from(params.n()) {
      Err(DkgError::IncorrectAmountOfVerificationShares {
        n: params.n(),
        shares: verification_shares.len(),
      })?;
    }
    for participant in verification_shares.keys().copied() {
      if u16::from(participant) > params.n() {
        Err(DkgError::InvalidParticipant { n: params.n(), participant })?;
      }
    }

    match &interpolation {
      Interpolation::Constant(_) => {
        if params.t() != params.n() {
          Err(DkgError::InapplicableInterpolation("constant interpolation for keys where t != n"))?;
        }
      }
      Interpolation::Lagrange => {}
    }

    let t = (1 ..= params.t()).map(Participant).collect::<Vec<_>>();
    let group_key =
      t.iter().map(|i| verification_shares[i] * interpolation.interpolation_factor(*i, &t)).sum();

    Ok(ThresholdKeys {
      core: Arc::new(Zeroizing::new(ThresholdCore {
        params,
        interpolation,
        secret_share,
        group_key,
        verification_shares,
      })),
      scalar: C::F::ONE,
      offset: C::F::ZERO,
    })
  }
```
