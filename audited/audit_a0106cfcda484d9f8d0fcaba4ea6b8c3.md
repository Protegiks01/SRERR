### Title
Undocumented Panic in IetfTranscript::rng_seed() Reachable Through Public API

### Summary
The `IetfTranscript::rng_seed()` method contains an `unimplemented!()` macro that will cause a panic if called. This method is reachable through the public API by creating an `IetfSchnorr` algorithm instance and calling `Algorithm::transcript().rng_seed()`. While the internal comment indicates this "shouldn't be used outside of FROST," no user-facing documentation warns about this limitation.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** The `IetfTranscript` type implements the `Transcript` trait from the `flexible-transcript` crate. The `rng_seed()` method is left unimplemented because FROST's internal signing flow doesn't require it. [2](#0-1) 

**Public API Exposure:**
1. `IetfSchnorr` is exposed as a public type alias [3](#0-2) 
2. The `Algorithm` trait with its `transcript()` method is public [4](#0-3) 
3. The `Transcript` trait defining `rng_seed()` is public [5](#0-4) 
4. Users can construct `IetfSchnorr` via the public `ietf()` constructor [6](#0-5) 

**Why Mitigations Fail:** The internal code comment is not user-facing documentation. The `IetfSchnorr` type documentation warns about its naive transcript format but does not mention the `rng_seed()` limitation. [7](#0-6) 

### Impact Explanation

**Affected Users:** Application developers who create `IetfSchnorr` instances and call transcript methods directly before passing the algorithm to the FROST signing machinery.

**Concrete Impact:** A panic will crash the thread or process when `rng_seed()` is invoked, causing a local denial of service. This does not compromise cryptographic security, leak secrets, or affect other participants in the FROST protocol.

**Severity Justification:** Low severity per the audit scope's explicit inclusion of "Undocumented panic reachable from a public API." The impact is limited to local process crashes with no security implications for the FROST protocol itself.

### Likelihood Explanation

**Exploitation Prerequisites:**
- User must depend on both `modular-frost` and `flexible-transcript` crates
- User must bring the `Transcript` trait into scope
- User must call `transcript().rng_seed()` on an `IetfSchnorr` instance

**Attack Complexity:** Low - straightforward API calls, but requires deliberate action with no practical benefit.

**Realistic Likelihood:** Very low. Normal FROST usage patterns pass the algorithm directly to `AlgorithmMachine::new()` which consumes it. [8](#0-7)  Users have no legitimate reason to call `rng_seed()` on a FROST signing algorithm's transcript before signing.

**Detection:** The panic will be immediately apparent during development/testing if triggered.

### Recommendation

**Primary Fix:** Add explicit documentation to the `IetfSchnorr` type and/or the `IetfTranscript` implementation warning that `rng_seed()` is not supported:

```rust
/// IETF-compliant Schnorr signature algorithm.
///
/// This algorithm specifically uses the transcript format defined in the FROST IETF draft.
/// It's a naive transcript format not viable for usage in larger protocols, yet is presented here
/// in order to provide compatibility.
///
/// **Note:** The underlying `IetfTranscript` does not support the `rng_seed()` method.
/// Calling `transcript().rng_seed()` will panic. FROST's internal signing flow does not
/// require this method.
///
/// Usage of this with key offsets will break the intended compatibility as the IETF draft does not
/// specify a protocol for offsets.
pub type IetfSchnorr<C, H> = Schnorr<C, IetfTranscript, H>;
```

**Alternative:** Implement `rng_seed()` by delegating to `challenge()` as other transcript implementations do, or explicitly panic with a descriptive error message rather than `unimplemented!()`.

**Testing:** Add a test that verifies the documented behavior or confirms the panic occurs with a clear message.

### Proof of Concept

```rust
use modular_frost::algorithm::{IetfSchnorr, Algorithm};
use flexible_transcript::Transcript;
use modular_frost::curve::Secp256k1; // Example curve
// Assume SomeHram is a valid Hram implementation

fn trigger_panic() {
    let mut algo = IetfSchnorr::<Secp256k1, SomeHram>::ietf();
    
    // Call the public Algorithm::transcript() method
    let transcript = algo.transcript();
    
    // Call rng_seed() from the Transcript trait
    // This will panic with: thread 'main' panicked at 'not implemented'
    let _seed = transcript.rng_seed(b"test_label");
}
```

**Expected Behavior:** Panic with "not implemented" message.

**Actual Behavior:** Panic occurs as described, confirming the undocumented panic is reachable through public APIs.

### Citations

**File:** crypto/frost/src/algorithm.rs (L28-38)
```rust
pub trait Algorithm<C: Curve>: Send + Sync {
  /// The transcript format this algorithm uses. This likely should NOT be the IETF-compatible
  /// transcript included in this crate.
  type Transcript: Sync + Clone + Debug + Transcript;
  /// Serializable addendum, used in algorithms requiring more data than just the nonces.
  type Addendum: Addendum;
  /// The resulting type of the signatures this algorithm will produce.
  type Signature: Clone + PartialEq + Debug;

  /// Obtain a mutable borrow of the underlying transcript.
  fn transcript(&mut self) -> &mut Self::Transcript;
```

**File:** crypto/frost/src/algorithm.rs (L121-124)
```rust
    // FROST won't use this and this shouldn't be used outside of FROST
    fn rng_seed(&mut self, _: &'static [u8]) -> [u8; 32] {
      unimplemented!()
    }
```

**File:** crypto/frost/src/algorithm.rs (L147-154)
```rust
/// IETF-compliant Schnorr signature algorithm.
///
/// This algorithm specifically uses the transcript format defined in the FROST IETF draft.
/// It's a naive transcript format not viable for usage in larger protocols, yet is presented here
/// in order to provide compatibility.
///
/// Usage of this with key offsets will break the intended compatibility as the IETF draft does not
/// specify a protocol for offsets.
```

**File:** crypto/frost/src/algorithm.rs (L155-155)
```rust
pub type IetfSchnorr<C, H> = Schnorr<C, IetfTranscript, H>;
```

**File:** crypto/frost/src/algorithm.rs (L164-170)
```rust
impl<C: Curve, H: Hram<C>> IetfSchnorr<C, H> {
  /// Construct a IETF-compatible Schnorr algorithm.
  ///
  /// Please see the `IetfSchnorr` documentation for the full details of this.
  pub fn ietf() -> IetfSchnorr<C, H> {
    Schnorr::new(IetfTranscript(vec![]))
  }
```

**File:** crypto/transcript/src/lib.rs (L46-53)
```rust
  /// Produce a RNG seed.
  ///
  /// Helper function for parties needing to generate random data from an agreed upon state.
  ///
  /// Implementors MAY internally call the challenge function for the needed bytes, and accordingly
  /// produce a transcript conflict between two transcripts, one which called challenge(label) and
  /// one which called rng_seed(label) at the same point.
  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32];
```

**File:** crypto/frost/src/tests/mod.rs (L242-243)
```rust
  let machines = algorithm_machines(&mut *rng, &IetfSchnorr::<C, H>::ietf(), keys);
  let sig = sign(&mut *rng, &IetfSchnorr::<C, H>::ietf(), keys.clone(), machines, MSG);
```
