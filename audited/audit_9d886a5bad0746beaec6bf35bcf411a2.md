### Title
Non-Constant-Time Table Lookup in Straus and Pippenger Multiexponentiation Algorithms

### Summary
The `straus()` and `pippenger()` functions in the multiexp crate use direct array indexing to access precomputed tables based on secret scalar bits, creating a cache timing side-channel vulnerability. Despite the design intent for constant-time operation (evidenced by separate `_vartime` variants and `Zeroize` trait bounds), the implementations fail to use constant-time table lookup mechanisms, potentially leaking private key or nonce material through cache timing attacks.

### Finding Description

**Exact Code Locations:**

1. [1](#0-0) 

2. [2](#0-1) 

**Root Cause:**

Both algorithms use standard Rust array indexing (`tables[s][index]` and `buckets[index]`) where the index is derived from secret scalar bits obtained via `prep_bits()`. [3](#0-2) 

Standard array indexing in Rust performs a memory access at `base_address + index * element_size`, which is not constant-time. The CPU cache behavior depends on which memory addresses are accessed, creating a timing side-channel that leaks information about the index values.

**Why Existing Mitigations Fail:**

While the codebase demonstrates awareness of timing security through use of `black_box` [4](#0-3)  and `zeroize` operations [5](#0-4) , these mitigations only prevent compiler optimizations and ensure memory cleanup—they do NOT make the table lookup constant-time.

The codebase includes a proper constant-time table lookup pattern in the Ed448 implementation using `conditional_select`: [6](#0-5) 

However, this pattern is not used in the multiexp algorithms.

**API Contract Indicates Secret Data Handling:**

The `multiexp()` function signature explicitly requires `Zeroize` trait bounds on both the group element and scalar types: [7](#0-6) 

In contrast, `multiexp_vartime()` does not require `Zeroize`: [8](#0-7) 

This design clearly indicates that `multiexp()` is intended for use with secret data, but the implementation fails to provide the necessary constant-time guarantees.

### Impact Explanation

**Specific Harm:**

If `multiexp()` is called with secret scalars (private keys, nonces, or secret shares), an attacker capable of measuring cache timing can potentially:

1. Observe which table entries are accessed during computation
2. Reconstruct the window-sized bit groups of the secret scalars
3. Recover the complete secret scalar values over multiple observations
4. Compromise private keys, leading to unauthorized transaction signing and fund theft
5. Compromise nonces, potentially enabling signature forgery in threshold signing protocols

**Affected Parties:**

- Validators running Serai nodes who use threshold signatures
- Users whose funds are controlled by compromised validator keys
- The protocol's security model, which relies on secret share confidentiality

**Severity Justification:**

Per the audit scope, this issue is classified as **Low severity**: "Non-constant time implementation with respect to secret data." [9](#0-8) 

The comment explicitly acknowledges the possibility of private values in the batch verifier.

### Likelihood Explanation

**Required Attacker Capabilities:**

1. **Physical or co-location access**: Attacker must run code on the same CPU or share cache with the victim process
2. **Timing measurement**: Ability to perform high-resolution cache timing measurements (e.g., Flush+Reload, Prime+Probe)
3. **Multiple observations**: Need multiple signing operations to extract complete key material
4. **Known or chosen messages**: May need to influence the messages being signed

**Attack Complexity:**

- **Medium to High**: Cache timing attacks require specialized knowledge and tooling
- Execution environment affects exploitability (cloud VMs are more vulnerable than dedicated hardware)
- Modern CPUs have some mitigations (e.g., partitioned caches), but attacks remain feasible

**Economic Feasibility:**

- Low cost for attackers with co-location access (e.g., cloud infrastructure)
- High potential gain if validator keys controlling significant funds are compromised

**Detection Risk:**

- Cache timing attacks are generally difficult to detect
- No audit trails or anomalous behavior visible to monitoring systems

### Recommendation

**Primary Fix: Implement Constant-Time Table Lookup**

Replace direct array indexing with constant-time selection using the `subtle` crate's `ConditionallySelectable` trait, following the pattern already implemented in Ed448:

In `straus.rs`, replace line 43:
- Scan all table entries and use `conditional_select` with constant-time equality check
- Pattern: Iterate through all possible indices and conditionally select the matching entry

In `pippenger.rs`, replace line 26:
- Apply the same constant-time bucket selection pattern

**Alternative Mitigation:**

If constant-time table lookup proves too expensive performance-wise:
1. Document that `multiexp()` should NOT be used with secret data
2. Remove `Zeroize` trait bounds from the constant-time variant
3. Ensure all internal uses with secret data use single scalar multiplication (`*` operator) instead, which is constant-time for Ed448 and Dalek curves

**Testing Recommendations:**

1. Implement timing variance tests comparing operations with different scalar bit patterns
2. Add integration tests verifying `multiexp()` is not called with secret keys/nonces in production code paths
3. Perform cache timing analysis using tools like cachegrind to verify constant-time behavior

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup Phase:**
   - Attacker gains co-location with victim validator (e.g., same cloud host)
   - Calibrate cache timing measurements for the victim's hardware

2. **Measurement Phase:**
   For each signing operation:
   - Trigger the victim to perform multiexp with secret scalar
   - Use Flush+Reload or Prime+Probe to monitor cache lines corresponding to table storage
   - Record which cache lines are accessed (indicates which table indices were used)
   - Map cache line accesses back to window-sized bit groups

3. **Recovery Phase:**
   - Collect measurements from multiple signing operations
   - Reconstruct the secret scalar's bit representation from observed table access patterns
   - For window size 4 (typical), each observation reveals 4 bits per scalar per table position
   - With sufficient observations, recover the complete secret key or nonce

**Expected vs Actual Behavior:**

- **Expected (constant-time)**: All cache timing measurements should show uniform access patterns regardless of scalar values
- **Actual (vulnerable)**: Cache timing reveals which specific table entries are accessed, leaking scalar bit information

**Realistic Parameters:**

- Window size: 3-8 (as configured by algorithm selection) [10](#0-9) 
- Scalar size: 256 bits (typical for most curves)
- Required observations: ~64-256 signing operations (depends on window size and noise)

### Citations

**File:** crypto/multiexp/src/straus.rs (L43-43)
```rust
      res += tables[s][usize::from(groupings[s][b])];
```

**File:** crypto/multiexp/src/straus.rs (L47-48)
```rust
  groupings.zeroize();
  tables.zeroize();
```

**File:** crypto/multiexp/src/pippenger.rs (L26-26)
```rust
      buckets[usize::from(bits[p][n])] += pairs[p].1;
```

**File:** crypto/multiexp/src/lib.rs (L39-50)
```rust
fn u8_from_bool(bit_ref: &mut bool) -> u8 {
  let bit_ref = black_box(bit_ref);

  let mut bit = black_box(*bit_ref);
  #[allow(clippy::cast_lossless)]
  let res = black_box(bit as u8);
  bit.zeroize();
  debug_assert!((res | 1) == 1);

  bit_ref.zeroize();
  res
}
```

**File:** crypto/multiexp/src/lib.rs (L54-74)
```rust
pub(crate) fn prep_bits<G: Group<Scalar: PrimeFieldBits>>(
  pairs: &[(G::Scalar, G)],
  window: u8,
) -> Vec<Vec<u8>> {
  let w_usize = usize::from(window);

  let mut groupings = vec![];
  for pair in pairs {
    let p = groupings.len();
    let mut bits = pair.0.to_le_bits();
    groupings.push(vec![0; bits.len().div_ceil(w_usize)]);

    for (i, mut bit) in bits.iter_mut().enumerate() {
      let mut bit = u8_from_bool(&mut bit);
      groupings[p][i / w_usize] |= bit << (i % w_usize);
      bit.zeroize();
    }
  }

  groupings
}
```

**File:** crypto/multiexp/src/lib.rs (L129-176)
```rust
fn algorithm(len: usize) -> Algorithm {
  #[cfg(not(debug_assertions))]
  if len == 0 {
    Algorithm::Null
  } else if len == 1 {
    Algorithm::Single
  } else if len < 10 {
    // Straus 2 never showed a performance benefit, even with just 2 elements
    Algorithm::Straus(3)
  } else if len < 20 {
    Algorithm::Straus(4)
  } else if len < 50 {
    Algorithm::Straus(5)
  } else if len < 100 {
    Algorithm::Pippenger(4)
  } else if len < 125 {
    Algorithm::Pippenger(5)
  } else if len < 275 {
    Algorithm::Pippenger(6)
  } else if len < 400 {
    Algorithm::Pippenger(7)
  } else {
    Algorithm::Pippenger(8)
  }

  #[cfg(debug_assertions)]
  if len == 0 {
    Algorithm::Null
  } else if len == 1 {
    Algorithm::Single
  } else if len < 10 {
    Algorithm::Straus(3)
  } else if len < 80 {
    Algorithm::Straus(4)
  } else if len < 100 {
    Algorithm::Straus(5)
  } else if len < 125 {
    Algorithm::Pippenger(4)
  } else if len < 275 {
    Algorithm::Pippenger(5)
  } else if len < 475 {
    Algorithm::Pippenger(6)
  } else if len < 750 {
    Algorithm::Pippenger(7)
  } else {
    Algorithm::Pippenger(8)
  }
}
```

**File:** crypto/multiexp/src/lib.rs (L180-189)
```rust
pub fn multiexp<G: Zeroize + Group<Scalar: Zeroize + PrimeFieldBits>>(
  pairs: &[(G::Scalar, G)],
) -> G {
  match algorithm(pairs.len()) {
    Algorithm::Null => Group::identity(),
    Algorithm::Single => pairs[0].1 * pairs[0].0,
    // These functions panic if called without any pairs
    Algorithm::Straus(window) => straus(pairs, window),
    Algorithm::Pippenger(window) => pippenger(pairs, window),
  }
```

**File:** crypto/multiexp/src/lib.rs (L194-200)
```rust
pub fn multiexp_vartime<G: Group<Scalar: PrimeFieldBits>>(pairs: &[(G::Scalar, G)]) -> G {
  match algorithm(pairs.len()) {
    Algorithm::Null => Group::identity(),
    Algorithm::Single => pairs[0].1 * pairs[0].0,
    Algorithm::Straus(window) => straus_vartime(pairs, window),
    Algorithm::Pippenger(window) => pippenger_vartime(pairs, window),
  }
```

**File:** crypto/ed448/src/point.rs (L258-266)
```rust
        let mut add_by = Point::identity();
        #[allow(clippy::needless_range_loop)]
        for i in 0 .. 16 {
          #[allow(clippy::cast_possible_truncation)] // Safe since 0 .. 16
          {
            add_by = <_>::conditional_select(&add_by, &table[i], bits.ct_eq(&(i as u8)));
          }
        }
        res += add_by;
```

**File:** crypto/multiexp/src/batch.rs (L13-19)
```rust
// Wrapped in Zeroizing in case any of the included statements contain private values.
#[allow(clippy::type_complexity)]
fn flat<Id: Copy + Zeroize, G: Zeroize + Group<Scalar: Zeroize + PrimeFieldBits>>(
  slice: &[(Id, Vec<(G::Scalar, G)>)],
) -> Zeroizing<Vec<(G::Scalar, G)>> {
  Zeroizing::new(slice.iter().flat_map(|pairs| pairs.1.iter()).copied().collect::<Vec<_>>())
}
```
