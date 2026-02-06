### Title
Unbounded Schnorr Aggregate Verification Enables CPU Exhaustion DoS via Malicious Commits

### Summary
An attacker controlling a validator's P2P identity can craft malicious Tendermint commits containing hundreds of thousands of validator signatures, causing victim validators to perform computationally expensive multiexp operations before validation fails. The unbounded deserialization of `Commit.validators` and `SchnorrAggregate.Rs` allows commits far exceeding the legitimate 150-validator limit, enabling sustained CPU exhaustion attacks that disrupt consensus.

### Finding Description

The vulnerability exists in the Tendermint commit verification flow where `SchnorrAggregate::verify()` performs batch verification using `multiexp_vartime()` on an unbounded number of signatures. [1](#0-0) 

The `verify()` function creates `2 * keys_and_challenges.len() + 1` pairs for the multiexp operation without any size validation. The number of pairs is directly proportional to the number of signatures being verified. [2](#0-1) 

The root cause is that `SchnorrAggregate::read()` deserializes an unbounded number of R values based on a u32 length prefix: [3](#0-2) 

Similarly, the `Commit` struct uses an unbounded `Vec` for validators: [4](#0-3) 

When validators receive synced blocks via P2P heartbeat mechanism, commits are deserialized without size validation: [5](#0-4) 

The `verify_commit()` function calls `verify_aggregate()` before checking validator legitimacy: [6](#0-5) 

This means the expensive multiexp operation occurs even for commits with arbitrary numbers of invalid validators. The `verify_aggregate()` implementation passes all signers to the aggregate verification: [7](#0-6) 

While legitimate validator sets are bounded to `MAX_KEY_SHARES_PER_SET = 150`: [8](#0-7) 

This limit is not enforced during commit deserialization from untrusted P2P input. The libp2p message size limit allows commits with hundreds of thousands of validators: [9](#0-8) [10](#0-9) 

With `BLOCKS_PER_BATCH = 11` and a 33MB message size limit, an attacker can send approximately 515,000 validator IDs per commit, resulting in over 1 million multiexp pairs. [11](#0-10) 

### Impact Explanation

**Affected Parties:** All validators in a Tributary set are vulnerable to this attack.

**Concrete Harm:**
1. CPU exhaustion on victim validators from multiexp operations with 1M+ pairs
2. Delayed or failed block verification preventing consensus progress
3. Potential chain halt if multiple validators are simultaneously attacked
4. Cascading effects as validators fall behind and request more malicious synced blocks

**Severity Justification:** MEDIUM
- Direct availability impact on consensus infrastructure
- Can disrupt Tributary consensus and delay cross-chain operations
- No funds are directly at risk, but prolonged DoS could prevent legitimate withdrawals
- Affects core validator functionality during the verification path

### Likelihood Explanation

**Required Attacker Capabilities:**
- Must be a validator in the target Tributary set OR compromise a validator's P2P identity
- Knowledge of Tributary genesis hash and message formats
- Ability to craft SCALE-encoded messages

**Attack Complexity:** LOW
1. Attacker generates N valid Ristretto group points for validator IDs
2. Constructs `SchnorrAggregate` with N corresponding R values and arbitrary scalar
3. Encodes `Commit` with these validators and aggregate signature
4. Wraps in `HeartbeatBatch` and sends via P2P to victim validators
5. Repeats to sustain CPU exhaustion

**Economic Feasibility:**
- Attack cost is minimal (network bandwidth for 33MB messages)
- No slashing risk since malformed commits simply fail verification
- Can be automated and sustained indefinitely

**Detection Risk:** Currently low - no rate limiting or anomaly detection on P2P messages: [12](#0-11) 

### Recommendation

**Primary Fix:** Add strict size validation before expensive operations:

1. In `verify_commit()`, reject commits exceeding `MAX_KEY_SHARES_PER_SET`:
```rust
if commit.validators.len() > MAX_KEY_SHARES_PER_SET as usize {
  return false;
}
```

2. In `SchnorrAggregate::read()`, enforce a maximum R count:
```rust
let len = u32::from_le_bytes(len);
if len > MAX_AGGREGATE_SIZE {
  return Err(io::Error::new(io::ErrorKind::InvalidData, "aggregate too large"));
}
```

3. In `verify_aggregate()`, add early bounds checking:
```rust
if signers.len() > MAX_KEY_SHARES_PER_SET as usize {
  return false;
}
```

**Secondary Mitigations:**
- Implement per-peer rate limiting on P2P messages
- Add authentication to restrict P2P connections to known validators
- Monitor and alert on commits with unusual validator counts

**Testing Recommendations:**
- Unit test rejecting commits with >150 validators
- Integration test P2P handling of oversized aggregates
- Benchmark multiexp performance degradation vs input size
- Verify no legitimate commits are rejected by new limits

### Proof of Concept

**Exploitation Algorithm:**

```
1. Generate malicious commit:
   N = 500,000  // Well within 33MB message limit
   
   validators = []
   Rs = []
   for i in 0..N:
     // Generate random valid Ristretto point
     validators[i] = random_ristretto_point().to_bytes()
     Rs[i] = random_ristretto_point()
   
   // Arbitrary scalar since signature will be invalid anyway
   s = random_scalar()
   
   aggregate = SchnorrAggregate { Rs, s }
   commit = Commit {
     end_time: current_time(),
     validators,
     signature: aggregate.serialize()
   }

2. Construct and send HeartbeatBatch:
   batch = HeartbeatBatch {
     blocks: [BlockCommit {
       block: minimal_valid_block(),
       commit: commit.encode()
     }],
     timestamp: current_time()
   }
   
   send_p2p_message(victim_validator, ReqResMessageKind::Block, batch.encode())

3. Victim processing:
   - Deserializes batch (no size check)
   - Calls tributary.sync_block(block, commit)
   - verify_commit() is invoked
   - verify_aggregate() deserializes 500,000 Rs
   - aggregate.verify() creates 1,000,001 multiexp pairs
   - multiexp_vartime() executes, consuming significant CPU
   - Returns false, but damage is done

4. Repeat attack:
   - Send multiple batches to sustain CPU load
   - Target multiple validators simultaneously
   - Monitor victim's block height to confirm DoS effect
```

**Expected Behavior:** Commit verification fails quickly after minimal validation

**Actual Behavior:** Expensive multiexp operation completes before validation fails, consuming excessive CPU time proportional to attacker-controlled input size

### Citations

**File:** crypto/schnorr/src/aggregate.rs (L77-88)
```rust
  pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;

    #[allow(non_snake_case)]
    let mut Rs = vec![];
    for _ in 0 .. u32::from_le_bytes(len) {
      Rs.push(C::read_G(reader)?);
    }

    Ok(SchnorrAggregate { Rs, s: C::read_F(reader)? })
  }
```

**File:** crypto/schnorr/src/aggregate.rs (L127-146)
```rust
  pub fn verify(&self, dst: &'static [u8], keys_and_challenges: &[(C::G, C::F)]) -> bool {
    if self.Rs.len() != keys_and_challenges.len() {
      return false;
    }

    let mut digest = DigestTranscript::<C::H>::new(dst);
    digest.domain_separate(b"signatures");
    for (_, challenge) in keys_and_challenges {
      digest.append_message(b"challenge", challenge.to_repr());
    }

    let mut pairs = Vec::with_capacity((2 * keys_and_challenges.len()) + 1);
    for (i, (key, challenge)) in keys_and_challenges.iter().enumerate() {
      let z = weight(&mut digest);
      pairs.push((z, self.Rs[i]));
      pairs.push((z * challenge, *key));
    }
    pairs.push((-self.s, C::generator()));
    multiexp_vartime(&pairs).is_identity().into()
  }
```

**File:** coordinator/tributary/tendermint/src/ext.rs (L135-142)
```rust
pub struct Commit<S: SignatureScheme> {
  /// End time of the round which created this commit, used as the start time of the next block.
  pub end_time: u64,
  /// Validators participating in the signature.
  pub validators: Vec<S::ValidatorId>,
  /// Aggregate signature.
  pub signature: S::AggregateSignature,
}
```

**File:** coordinator/tributary/tendermint/src/ext.rs (L256-275)
```rust
  fn verify_commit(
    &self,
    id: <Self::Block as Block>::Id,
    commit: &Commit<Self::SignatureScheme>,
  ) -> bool {
    if commit.validators.iter().collect::<HashSet<_>>().len() != commit.validators.len() {
      return false;
    }

    if !self.signature_scheme().verify_aggregate(
      &commit.validators,
      &commit_msg(commit.end_time, id.as_ref()),
      &commit.signature,
    ) {
      return false;
    }

    let weights = self.weights();
    commit.validators.iter().map(|v| weights.weight(*v)).sum::<u64>() >= weights.threshold()
  }
```

**File:** coordinator/src/p2p.rs (L52-53)
```rust
const MAX_LIBP2P_REQRES_MESSAGE_SIZE: usize =
  (tributary::BLOCK_SIZE_LIMIT * BLOCKS_PER_BATCH) + 1024;
```

**File:** coordinator/src/p2p.rs (L69-70)
```rust
// Maximum amount of blocks to send in a batch
const BLOCKS_PER_BATCH: usize = BLOCKS_PER_MINUTE + 1;
```

**File:** coordinator/src/p2p.rs (L376-377)
```rust
    // TODO: Do we want to add a custom authentication protocol to only accept connections from
    // fellow validators? Doing so would reduce the potential for spam
```

**File:** coordinator/src/p2p.rs (L982-995)
```rust
                      for bc in batch.blocks {
                        // TODO: why do we use ReadWrite instead of Encode/Decode for blocks?
                        // Should we use the same for batches so we can read both at the same time?
                        let Ok(block) = Block::<Transaction>::read(&mut bc.block.as_slice()) else {
                          log::error!("received block message with an invalidly serialized block");
                          continue;
                        };

                        let res = tributary.tributary.sync_block(block, bc.commit).await;
                        log::debug!(
                          "received block from {:?}, sync_block returned {}",
                          msg.sender,
                          res
                        );
```

**File:** coordinator/tributary/src/tendermint/mod.rs (L200-229)
```rust
  #[must_use]
  fn verify_aggregate(
    &self,
    signers: &[Self::ValidatorId],
    msg: &[u8],
    sig: &Self::AggregateSignature,
  ) -> bool {
    let Ok(aggregate) = SchnorrAggregate::<Ristretto>::read::<&[u8]>(&mut sig.as_slice()) else {
      return false;
    };

    if signers.len() != aggregate.Rs().len() {
      return false;
    }

    let mut challenges = vec![];
    for (key, nonce) in signers.iter().zip(aggregate.Rs()) {
      challenges.push(challenge(self.genesis, *key, nonce.to_bytes().as_ref(), msg));
    }

    aggregate.verify(
      DST,
      signers
        .iter()
        .zip(challenges)
        .map(|(s, c)| (<Ristretto as Ciphersuite>::read_G(&mut s.as_slice()).unwrap(), c))
        .collect::<Vec<_>>()
        .as_slice(),
    )
  }
```

**File:** substrate/validator-sets/primitives/src/lib.rs (L22-23)
```rust
/// The maximum amount of key shares per set.
pub const MAX_KEY_SHARES_PER_SET: u32 = 150;
```

**File:** coordinator/tributary/src/lib.rs (L60-60)
```rust
pub const BLOCK_SIZE_LIMIT: usize = 3_001_000;
```
