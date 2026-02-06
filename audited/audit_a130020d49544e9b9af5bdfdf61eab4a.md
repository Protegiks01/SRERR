### Title
Bitcoin Network Partition Causes Tributary Consensus Failure Due to Independent Block Scanning

### Summary
During Bitcoin network partitions, validators independently scan their own Bitcoin nodes without coordination, leading to different validators creating batches with different block hashes for the same batch ID. This causes Tributary consensus to fail as validators reject blocks containing different provided transactions, permanently halting the coordinator.

### Finding Description

**Root Cause:**
Each validator's processor independently queries its own Bitcoin RPC node to determine which blocks to scan. [1](#0-0)  When a Bitcoin network partition occurs, different Bitcoin nodes may be on different forks, causing validators to scan different blocks at the same block number.

The scanner fetches blocks by number and obtains the block ID (hash): [2](#0-1) 

This block hash is then copied directly into the Batch structure without any coordination between validators: [3](#0-2) 

The Batch's block hash is propagated through BatchPreprocess messages to the coordinator, which creates Transaction::Batch with this hash: [4](#0-3) 

The Transaction::Batch is defined as a provided transaction containing the block hash: [5](#0-4) 

**Why Consensus Fails:**
When the Tributary processes proposed blocks, it verifies that provided transactions match local expectations. If validators have different locally provided transactions, block verification fails: [6](#0-5) 

When a validator's local Transaction::Batch doesn't match what's in the proposed block, the verification returns `BlockError::DistinctProvided`, causing the validator to reject the block and not vote for it.

If consensus is eventually achieved with one block hash, validators on the losing side will later attempt to provide their different transaction and receive `ProvidedError::LocalMismatchesOnChain`, which triggers an infinite error loop: [7](#0-6) 

**Why Existing Mitigations Fail:**

The reorg detection only catches when a single validator sees different blocks at the same height over time: [8](#0-7)  This doesn't prevent different validators from being on different forks simultaneously.

The 6-block confirmation requirement only ensures probabilistic finality on each individual fork: [9](#0-8)  It doesn't prevent validators from scanning different forks.

### Impact Explanation

**Specific Harm:**
- Complete halt of Serai's Bitcoin integration - all Bitcoin deposits cannot be processed into sriXYZ
- Validators on the minority fork enter an infinite error loop with no recovery mechanism
- Tributary consensus permanently stalls if no 2/3+ majority exists on a single fork
- All pending Bitcoin operations (deposits and withdrawals) become blocked

**Affected Parties:**
- All users attempting to bridge Bitcoin to/from Serai
- Validators that witness the minority fork (permanently stuck)
- The entire Serai network's Bitcoin operations

**Quantified Impact:**
- 100% of Bitcoin batch operations halt
- All Bitcoin deposits cannot be minted as sriXYZ until manual intervention
- Affected validators require restart/manual recovery

**Severity Justification:**
This violates Critical Invariant #4 (batch correctness) by allowing validators to disagree on which external blocks batches map to. It causes complete consensus failure for Bitcoin operations without requiring an attacker.

### Likelihood Explanation

**Attack Prerequisites:**
- None - triggered by natural Bitcoin network conditions
- Bitcoin network partitions have occurred historically (2013, 2015 fork events)
- Any period of Bitcoin network instability can trigger this

**Realistic Exploitation:**
1. Bitcoin network experiences partition (naturally occurring event)
2. Some validators' Bitcoin nodes on Fork A, others on Fork B  
3. Both forks accumulate 6+ confirmations
4. Validators independently scan their respective forks
5. Different Transaction::Batch transactions created with different block hashes
6. Tributary consensus fails or affected validators enter infinite loops

**Economic Feasibility:**
- No attacker cost (natural occurrence)
- High likelihood during any Bitcoin network instability
- Even brief partitions during scanning windows can trigger

**Detection:**
- Immediately detected when Tributary consensus stalls
- Affected validators continuously log LocalMismatchesOnChain errors
- No automated recovery mechanism exists

### Recommendation

**Primary Fix:**
Implement validator coordination on Bitcoin block hashes before batch creation:

1. Add pre-batch coordination phase in Tributary:
   - Validators publish witnessed block hashes via unsigned transactions
   - Achieve Tendermint consensus on canonical block hash for each block number
   - Only create Transaction::Batch after consensus on block hash

2. Implement parent hash chain validation:
   - Require batches to prove chain continuity from previous agreed block
   - Reject batches with unverified parent relationships
   - Use longest chain / most work rules for fork resolution

3. Add recovery mechanism:
   - Replace infinite loop with alerting and manual intervention capability
   - Implement fork detection and automated resolution
   - Allow validators to resync and retry with consensus block hash

**Testing Recommendations:**
- Create integration test simulating Bitcoin network partition with validators on different forks
- Verify Tributary behavior with conflicting Transaction::Batch submissions
- Test recovery mechanisms and fork resolution logic
- Validate that 6-confirmation threshold applies to agreed-upon canonical chain

### Proof of Concept

**Setup:**
- 4 Serai validators (V1, V2, V3, V4)
- V1, V2 connected to Bitcoin Node A (Fork A)
- V3, V4 connected to Bitcoin Node B (Fork B, partitioned)
- Both forks at block height N with 6+ confirmations

**Exploitation Algorithm:**

1. Fork A block N-6 has hash `H_A = 0xAAA...AAA`
2. Fork B block N-6 has hash `H_B = 0xBBB...BBB`

3. V1, V2 scanners query `get_latest_block_number()` → N
4. V1, V2 scan block N-6, obtain hash H_A
5. V1, V2 create `Batch { id: 0, block: BlockHash(H_A), ... }`
6. V1, V2 coordinators create `Transaction::Batch { block: H_A, batch: 0 }`

7. V3, V4 scanners query `get_latest_block_number()` → N  
8. V3, V4 scan block N-6, obtain hash H_B
9. V3, V4 create `Batch { id: 0, block: BlockHash(H_B), ... }`
10. V3, V4 coordinators create `Transaction::Batch { block: H_B, batch: 0 }`

11. V1 (proposer) proposes Tributary block containing `Transaction::Batch { H_A, 0 }`

12. V3, V4 verify proposed block:
    - Pop local `Transaction::Batch { H_B, 0 }`
    - Compare to `Transaction::Batch { H_A, 0 }` in proposal
    - `H_A ≠ H_B` → Return `BlockError::DistinctProvided`
    - Reject block, don't vote

13. Result: 2-2 split, Tendermint cannot achieve 2/3+ (3/4) consensus
14. Tributary permanently stalls, no batches processed

**Alternative outcome (3-1 split):**
If V1, V2, V3 on Fork A and only V4 on Fork B:
- Block with H_A achieves consensus
- V4 later provides `Transaction::Batch { H_B, 0 }`
- Gets `ProvidedError::LocalMismatchesOnChain`
- V4 coordinator enters infinite error loop, logs every 60 seconds
- V4 permanently stuck until manual intervention

**Expected:** Validators coordinate on block hash before creating batches
**Actual:** Conflicting batches → consensus failure → system halt

### Citations

**File:** processor/src/multisigs/scanner.rs (L478-481)
```rust
            break match network.get_latest_block_number().await {
              // Only scan confirmed blocks, which we consider effectively finalized
              // CONFIRMATIONS - 1 as whatever's in the latest block already has 1 confirm
              Ok(latest) => latest.saturating_sub(N::CONFIRMATIONS.saturating_sub(1)),
```

**File:** processor/src/multisigs/scanner.rs (L510-514)
```rust
        let Ok(block) = network.get_block(block_being_scanned).await else {
          warn!("couldn't get block {block_being_scanned}");
          break;
        };
        let block_id = block.id();
```

**File:** processor/src/multisigs/scanner.rs (L521-534)
```rust
        if let Some(id) = ScannerDb::<N, D>::block(&db, block_being_scanned) {
          if id != block_id {
            panic!("reorg'd from finalized {} to {}", hex::encode(id), hex::encode(block_id));
          }
        } else {
          // TODO: Move this to an unwrap
          if let Some(id) = ScannerDb::<N, D>::block(&db, block_being_scanned.saturating_sub(1)) {
            if id != block.parent() {
              panic!(
                "block {} doesn't build off expected parent {}",
                hex::encode(block_id),
                hex::encode(id),
              );
            }
```

**File:** processor/src/multisigs/mod.rs (L975-985)
```rust
        let mut block_hash = [0; 32];
        block_hash.copy_from_slice(block.as_ref());
        let mut batch_id = NextBatchDb::get(txn).unwrap_or_default();

        // start with empty batch
        let mut batches = vec![Batch {
          network: N::NETWORK,
          id: batch_id,
          block: BlockHash(block_hash),
          instructions: vec![],
        }];
```

**File:** coordinator/src/main.rs (L648-654)
```rust
            let intended = Transaction::Batch {
              block: block.0,
              batch: match id.id {
                SubstrateSignableId::Batch(id) => id,
                _ => panic!("BatchPreprocess did not contain Batch ID"),
              },
            };
```

**File:** coordinator/src/main.rs (L748-758)
```rust
            if res == Err(ProvidedError::LocalMismatchesOnChain) {
              // Spin, since this is a crit for this Tributary
              loop {
                log::error!(
                  "{}. tributary: {}, provided: {:?}",
                  "tributary added distinct provided to delayed locally provided TX",
                  hex::encode(spec.genesis()),
                  &tx,
                );
                sleep(Duration::from_secs(60)).await;
              }
```

**File:** coordinator/src/tributary/transaction.rs (L172-175)
```rust
  Batch {
    block: [u8; 32],
    batch: u32,
  },
```

**File:** coordinator/tributary/src/block.rs (L219-229)
```rust
          if let Some(local) = locally_provided.get_mut(order).and_then(VecDeque::pop_front) {
            // Since this was a provided TX, it must be an application TX
            let Transaction::Application(tx) = tx else {
              Err(BlockError::NonLocalProvided(txs.pop().unwrap()))?
            };
            if tx != &local {
              Err(BlockError::DistinctProvided)?;
            }
          } else if !allow_non_local_provided {
            Err(BlockError::NonLocalProvided(txs.pop().unwrap()))?
          };
```

**File:** processor/src/networks/bitcoin.rs (L604-604)
```rust
  const CONFIRMATIONS: usize = 6;
```
