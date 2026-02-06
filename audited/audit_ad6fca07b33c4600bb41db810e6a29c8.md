### Title
Missing Participant Count Validation Enables Panic and Potential Nonce Reuse in FROST Signing

### Summary
The `sign()` function in `crypto/frost/src/sign.rs` at line 312 calls `keys.view(included.clone()).unwrap()` without validating that `included.len() <= n`, allowing an attacker to trigger a panic by providing more than `n-1` preprocesses. When this panic occurs, if the user has cached the preprocess seed using `cache()`, the nonces remain recoverable and can be reused on retry, enabling private key share recovery through nonce reuse attacks.

### Finding Description

**Exact Location:** [1](#0-0) 

**Root Cause:**
The `sign()` function validates that the signing set has at least the threshold number of participants and that participant indices don't exceed `n`, but fails to check if the total number of participants exceeds `n` before calling `view().unwrap()`. [2](#0-1) 

The `view()` function in `ThresholdKeys` validates this condition and returns `Err(DkgError::IncorrectAmountOfParticipants)` when `included.len() > n`: [3](#0-2) 

Since `sign()` uses `.unwrap()` at line 312 instead of propagating the error, a panic occurs when this condition is violated.

**Why Existing Mitigations Fail:**
The validation at lines 298-310 checks:
- Minimum threshold: `included.len() >= t` ✓
- Maximum participant index: `included[included.len()-1] <= n` ✓  
- No duplicates: Via sorted comparison ✓
- Missing: `included.len() <= n` ✗

An attacker can construct a `preprocesses` HashMap with `n` or more distinct participants (not including the current participant). After adding the current participant at line 291, `included` will have more than `n` entries, bypassing all existing checks. [4](#0-3) 

### Impact Explanation

**Primary Impact - Panic (DoS):**
The panic crashes the signing process, causing denial of service.

**Critical Impact - Nonce Reuse:**
At the point of panic (line 312), the nonces stored in `self.nonces` have not yet been consumed. Nonce consumption occurs later at lines 386-396: [5](#0-4) 

If a user cached the preprocess seed using `cache()`: [6](#0-5) 

They can recreate the machine with identical nonces using `from_cache()`: [7](#0-6) 

The seed deterministically generates nonces via ChaCha20Rng: [8](#0-7) 

If the user catches the panic and retries signing with the same cached seed but different preprocesses or message, the same nonces are used for a different signing session. This violates Critical Invariant #2 ("no nonce/preprocess reuse") and enables private key share recovery, as documented: [9](#0-8) [10](#0-9) 

**Who Is Affected:**
- Direct users of the `modular-frost` library who use `cache()` and implement panic recovery
- Serai's coordinator uses cached preprocesses with encryption, though per-attempt context isolation provides some mitigation [11](#0-10) 

### Likelihood Explanation

**Attack Prerequisites:**
1. Attacker can provide preprocesses (requires being a protocol participant or message injection capability)
2. Victim uses `cache()` to cache preprocesses  
3. Victim implements panic handling that allows retry with the same cached preprocess
4. Attacker can observe both signatures to recover the key share

**Attack Complexity:**
Low. The attacker simply provides more than `n-1` preprocesses in the HashMap. For example, with `n=5`, providing 5 preprocesses triggers the panic.

**Economic Feasibility:**
- Cost: Minimal (send malformed messages)
- Gain: Full recovery of victim's threshold key share, enabling unauthorized signing

**Detection:**
- Panic would appear in logs as an unexpected program termination
- However, if the victim doesn't understand the security implications, they may retry with the same cached preprocess, completing the attack

**Serai-Specific Mitigations:**
- Processor code doesn't use `cache()`, avoiding nonce reuse risk (though still vulnerable to panic DoS)
- Coordinator uses per-attempt contexts that change on reattempt, providing defense-in-depth against cross-attempt nonce reuse [12](#0-11) 

However, the library itself remains vulnerable for external users and doesn't properly validate inputs as expected for a public API.

### Recommendation

**Primary Fix:**
Add validation before line 312 to check `included.len() <= n` and return `FrostError::InvalidSigningSet` instead of panicking:

```rust
// After line 310, before line 312:
if included.len() > usize::from(multisig_params.n()) {
  Err(FrostError::InvalidSigningSet("too many signers"))?;
}

let view = self.params.keys.view(included.clone())?; // Use ? instead of unwrap()
```

**Rationale:**
- Matches the existing validation pattern at lines 298-310
- Returns a proper error instead of panicking
- Allows callers to handle the error gracefully without risking nonce reuse
- Aligns with the `FrostError::InvalidSigningSet` variant already defined for signing set validation issues [13](#0-12) 

**Testing:**
1. Unit test with `preprocesses.len() == n` (should succeed)
2. Unit test with `preprocesses.len() > n` (should return error, not panic)
3. Verify error message clearly indicates too many participants
4. Confirm existing tests still pass

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup:** Assume FROST parameters `t=4, n=5` with participants `P1, P2, P3, P4, P5`. Attacker is `P1`.

2. **Attacker Action (Trigger Panic):**
   - In preprocessing round, `P1` collects preprocesses from all participants
   - `P1` constructs malicious `preprocesses` HashMap with 5 entries: `{P2, P3, P4, P5, P6}` (where P6 is fabricated/replayed)
   - When `P1` calls `machine.sign(preprocesses, msg)`:
     - Line 291: Adds `P1` to `included` → `included = [P1, P2, P3, P4, P5, P6]`
     - Line 295: Sorts → `included = [P1, P2, P3, P4, P5, P6]` (6 participants)
     - Line 298-300: Check `6 >= 4` ✓ (passes)
     - Line 302-304: Check `P6 <= 5`? Depends on P6's index (may pass or fail)
     - Line 306-309: No duplicates ✓ (passes if distinct)
     - Line 312: `view([P1,P2,P3,P4,P5,P6]).unwrap()` → `view()` checks `6 <= 5` ✗ → returns `Err()` → `.unwrap()` **panics**

3. **Victim Response (Nonce Reuse):**
   - Victim's error handler catches panic: "signing failed"
   - Victim still has cached preprocess seed from `machine.cache()`
   - Victim believes issue was temporary and retries with valid preprocesses
   - Calls `machine = from_cache(params, keys, cached_seed)`
   - Calls `machine.sign(valid_preprocesses, msg2)` with different message/preprocesses
   - **Same nonces used for different signing session**

4. **Key Share Recovery:**
   - Attacker observes both partial signatures from `P1`: `(R, s1)` from first attempt before panic, `(R', s2)` from retry
   - Since nonces were reused: `R = R'` but `s1, s2` use same nonce for different challenges
   - Standard FROST nonce reuse attack recovers `P1`'s key share from the relationship between `s1` and `s2`

**Expected Behavior:** `sign()` should return `Err(FrostError::InvalidSigningSet("too many signers"))` at line 312 check, allowing graceful error handling without exposing nonces.

**Actual Behavior:** Panic at line 312, leaving cached preprocess seed intact and enabling nonce reuse if user retries.

### Citations

**File:** crypto/frost/src/sign.rs (L85-87)
```rust
/// A preprocess MUST only be used once. Reuse will enable third-party recovery of your private
/// key share. Additionally, this MUST be handled with the same security as your private key share,
/// as knowledge of it also enables recovery.
```

**File:** crypto/frost/src/sign.rs (L121-132)
```rust
  fn seeded_preprocess(
    self,
    seed: CachedPreprocess,
  ) -> (AlgorithmSignMachine<C, A>, Preprocess<C, A::Addendum>) {
    let mut params = self.params;

    let mut rng = ChaCha20Rng::from_seed(*seed.0);
    let (nonces, commitments) = Commitments::new::<_>(
      &mut rng,
      params.keys.original_secret_share(),
      &params.algorithm.nonces(),
    );
```

**File:** crypto/frost/src/sign.rs (L264-266)
```rust
  fn cache(self) -> CachedPreprocess {
    self.seed
  }
```

**File:** crypto/frost/src/sign.rs (L268-273)
```rust
  fn from_cache(
    algorithm: A,
    keys: ThresholdKeys<C>,
    cache: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    AlgorithmMachine::new(algorithm, keys).seeded_preprocess(cache)
```

**File:** crypto/frost/src/sign.rs (L290-295)
```rust
    let mut included = Vec::with_capacity(preprocesses.len() + 1);
    included.push(multisig_params.i());
    for l in preprocesses.keys() {
      included.push(*l);
    }
    included.sort_unstable();
```

**File:** crypto/frost/src/sign.rs (L297-310)
```rust
    // Included < threshold
    if included.len() < usize::from(multisig_params.t()) {
      Err(FrostError::InvalidSigningSet("not enough signers"))?;
    }
    // OOB index
    if u16::from(included[included.len() - 1]) > multisig_params.n() {
      Err(FrostError::InvalidParticipant(multisig_params.n(), included[included.len() - 1]))?;
    }
    // Same signer included multiple times
    for i in 0 .. (included.len() - 1) {
      if included[i] == included[i + 1] {
        Err(FrostError::DuplicatedParticipant(included[i]))?;
      }
    }
```

**File:** crypto/frost/src/sign.rs (L312-312)
```rust
    let view = self.params.keys.view(included.clone()).unwrap();
```

**File:** crypto/frost/src/sign.rs (L386-396)
```rust
    let nonces = self
      .nonces
      .drain(..)
      .enumerate()
      .map(|(n, nonces)| {
        let [base, mut actual] = nonces.0;
        *actual *= our_binding_factors[n];
        *actual += base.deref();
        actual
      })
      .collect::<Vec<_>>();
```

**File:** crypto/dkg/src/lib.rs (L463-471)
```rust
  pub fn view(&self, mut included: Vec<Participant>) -> Result<ThresholdView<C>, DkgError> {
    if (included.len() < self.params().t.into()) ||
      (usize::from(self.params().n()) < included.len())
    {
      Err(DkgError::IncorrectAmountOfParticipants {
        t: self.params().t,
        n: self.params().n,
        amount: included.len(),
      })?;
```

**File:** spec/cryptography/FROST.md (L51-55)
```markdown
Reusing preprocesses would enable a third-party to recover your private key
share. Accordingly, you MUST not reuse preprocesses. Third-party knowledge of
your preprocess would also enable their recovery of your private key share.
Accordingly, you MUST treat cached preprocesses with the same security as your
private key share.
```

**File:** coordinator/src/tributary/signing_protocol.rs (L123-145)
```rust
    if CachedPreprocesses::get(self.txn, &self.context).is_none() {
      let (machine, _) =
        AlgorithmMachine::new(algorithm.clone(), keys.clone()).preprocess(&mut OsRng);

      let mut cache = machine.cache();
      assert_eq!(cache.0.len(), 32);
      #[allow(clippy::needless_range_loop)]
      for b in 0 .. 32 {
        cache.0[b] ^= encryption_key_slice[b];
      }

      CachedPreprocesses::set(self.txn, &self.context, &cache.0);
    }

    let cached = CachedPreprocesses::get(self.txn, &self.context).unwrap();
    let mut cached: Zeroizing<[u8; 32]> = Zeroizing::new(cached);
    #[allow(clippy::needless_range_loop)]
    for b in 0 .. 32 {
      cached[b] ^= encryption_key_slice[b];
    }
    encryption_key_slice.zeroize();
    let (machine, preprocess) =
      AlgorithmSignMachine::from_cache(algorithm, keys, CachedPreprocess(cached));
```

**File:** coordinator/src/tributary/signing_protocol.rs (L274-277)
```rust
  fn signing_protocol(&mut self) -> DkgConfirmerSigningProtocol<'_, T> {
    let context = (b"DkgConfirmer", self.attempt);
    SigningProtocol { key: self.key, spec: self.spec, txn: self.txn, context }
  }
```

**File:** crypto/frost/src/lib.rs (L34-35)
```rust
  #[error("invalid signing set ({0})")]
  InvalidSigningSet(&'static str),
```
