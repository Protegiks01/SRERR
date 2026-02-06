### Title
Block Reorganization Handling Failure Leads to False Deposits and Permanent Processor Halt

### Summary
The Bitcoin processor scanner lacks proper block reorganization handling, leading to a permanent panic state when reorganizations occur after the confirmation depth. This enables false deposit processing and missed withdrawals, as block data is committed to the database before events are acknowledged, and there is no recovery mechanism for detected reorganizations.

### Finding Description

**Exact Code Location:**
The vulnerability exists in the scanner's block processing logic at `processor/src/multisigs/scanner.rs` lines 521-540 and the event emission flow. [1](#0-0) 

**Root Cause:**
The scanner saves block IDs to the database immediately upon first encountering a block, before events are acknowledged or batches are finalized. When a reorganization occurs, the scanner detects the mismatch between the stored block ID and the new block ID at the same height and panics with no recovery path. [2](#0-1) 

The critical sequence is:
1. Block N (hash H1) is scanned and immediately saved to the database
2. Outputs are detected and emitted as `ScannerEvent::Block`
3. Eventuality completions are detected and emitted as `ScannerEvent::Completed`
4. Events are processed, creating batches and marking completions in the signer database [3](#0-2) 

5. Block acknowledgment (`ack_block`) happens only after Serai confirms the batch [4](#0-3) 

If a reorganization occurs between steps 1-4 and step 5, the old block hash remains in the database while the chain has moved to a different block at that height. The scanner will permanently panic on the next iteration with no automatic recovery.

**Why Existing Mitigations Fail:**
The `CONFIRMATIONS` constant (set to 6 for Bitcoin) is intended to make blocks "effectively finalized", but this is a probabilistic guarantee, not absolute. [5](#0-4) [6](#0-5) 

The scanner only processes blocks with sufficient confirmations but provides no mechanism to handle reorganizations of those "finalized" blocks when they do occur. The panic is treated as a fatal error rather than a recoverable state.

### Impact Explanation

**Specific Harm:**
1. **False Deposits:** Outputs detected in the original block H1 may be processed into batches and minted on Serai even though they don't exist in the reorganized chain. This violates Critical Invariant #5 (Mint/burn accounting) and the "Reportedly received funds which were not actually received/spendable" critical scope.

2. **False Withdrawal Completions:** Eventuality completions detected in H1 are immediately saved to the database and reported to the coordinator. [7](#0-6) [8](#0-7) 

If the transaction doesn't exist in the reorganized chain, the system incorrectly marks the withdrawal as complete, potentially leading to double-spends or lost funds.

3. **Permanent Denial of Service:** After detecting a reorganization, the processor enters an unrecoverable panic loop, halting all block scanning and processing for the affected network.

**Severity Justification:**
This is a Critical vulnerability as it enables "Reportedly received funds which were not actually received/spendable" and violates Critical Invariant #4 (Batch correctness: batches map to finalized external blocks).

### Likelihood Explanation

**Required Capabilities:**
- For natural occurrence: None - 6-deep Bitcoin reorganizations have occurred historically (though rare)
- For malicious attack: Sufficient hashpower to cause a 6+ block reorganization (51% attack)

**Attack Complexity:**
1. Wait for deposits to be made to Serai's multisig on Bitcoin
2. Wait for blocks to reach 6 confirmations and be scanned
3. Execute or wait for a 6+ block reorganization that excludes the deposit transactions
4. The processor panics, but outputs may already be processed into batches
5. If batches were submitted to Serai before the reorganization, false sriXYZ is minted

**Economic Feasibility:**
While 6-deep reorganizations on Bitcoin mainnet are extremely rare, they are not theoretically impossible. Historical instances include the 2013 Bitcoin fork (>20 blocks). For an attacker with sufficient hashpower or during network instability, this becomes feasible, especially considering the potential gain of minting unbacked sriXYZ.

**Detection Risk:**
The panic is immediately visible in logs, but the damage (false deposits processed) may already be done before detection.

### Recommendation

**Primary Fix:**
Implement proper reorganization recovery in the scanner:

1. **Do not commit block IDs to the database until after acknowledgment** - Only save block IDs in the same transaction as `save_scanned_block` during `ack_block`

2. **Add reorganization detection and rollback** - When a mismatch is detected, instead of panicking:
   - Rollback RAM state to the last acknowledged block
   - Clear any unacknowledged events from the event queue
   - Rescan from the last acknowledged block forward

3. **Prevent event processing before acknowledgment** - Ensure batches are only created from outputs in acknowledged blocks, or implement a two-phase commit where events are tentative until acknowledged

**Alternative Mitigation:**
Increase `CONFIRMATIONS` to a much higher value (e.g., 100 blocks for Bitcoin) to make reorganizations practically impossible, though this significantly increases latency.

**Testing Recommendations:**
1. Simulate reorganizations in integration tests at various depths
2. Test recovery behavior when reorganizations occur during different phases of the scanning/acknowledgment cycle
3. Verify that outputs from reorganized blocks are not processed into batches

### Proof of Concept

**Exploitation Algorithm:**

```
1. Setup:
   - Deploy Serai with Bitcoin integration
   - Fund multisig with deposit transaction in block N

2. Wait for scanning:
   - Block N reaches 6 confirmations (block N+6 exists)
   - Scanner processes block N, emits outputs
   - Outputs are queued for batch creation

3. Trigger reorganization:
   - Before ack_block is called for block N
   - Execute 7-block reorganization excluding the deposit
   - New chain has block N' at height N (different hash)

4. Observe behavior:
   - Scanner.run attempts to scan block N again
   - Loads block_id = H1 from database (line 521)
   - Fetches new block with hash H2 from network (line 510)
   - Comparison H1 != H2 triggers panic (line 523)
   - Processor halts permanently

5. Impact:
   - If batch was created before reorg: false deposit minted on Serai
   - If eventuality was detected: false completion reported
   - System requires manual database intervention to recover
```

**Expected Behavior:**
Scanner should detect the reorganization, rollback unacknowledged state, and rescan from the last acknowledged block.

**Actual Behavior:**
Scanner panics with message "reorg'd from finalized {H1} to {H2}" and cannot recover without manual database modification.

### Citations

**File:** processor/src/multisigs/scanner.rs (L521-540)
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
          }

          let mut txn = db.txn();
          ScannerDb::<N, D>::save_block(&mut txn, block_being_scanned, &block_id);
          txn.commit();
        }
```

**File:** processor/src/multisigs/scanner.rs (L697-709)
```rust
        let sent_block = if has_activation || is_retirement_block || (!outputs.is_empty()) {
          // Save the outputs to disk
          let mut txn = db.txn();
          ScannerDb::<N, D>::save_outputs(&mut txn, &block_id, &outputs);
          txn.commit();

          // Send all outputs
          if !scanner.emit(ScannerEvent::Block { is_retirement_block, block: block_id, outputs }) {
            return;
          }

          // Since we're creating a Batch, mark it as needing ack
          scanner.need_ack.push_back(block_being_scanned);
```

**File:** processor/src/multisigs/mod.rs (L608-608)
```rust
        let (is_retirement_block, outputs) = self.scanner.ack_block(txn, block_id.clone()).await;
```

**File:** processor/src/multisigs/mod.rs (L1028-1031)
```rust
      ScannerEvent::Completed(key, block_number, id, tx_id, completion) => {
        ResolvedDb::resolve_plan::<N>(txn, &key, id, &tx_id);
        (block_number, MultisigEvent::Completed(key, id, completion))
      }
```

**File:** processor/src/networks/bitcoin.rs (L604-604)
```rust
  const CONFIRMATIONS: usize = 6;
```

**File:** spec/processor/Scanning.md (L1-9)
```markdown
# Scanning

Only blocks with finality, either actual or sufficiently probabilistic, are
operated upon. This is referred to as a block with `CONFIRMATIONS`
confirmations, the block itself being the first confirmation.

For chains which promise finality on a known schedule, `CONFIRMATIONS` is set to
`1` and each group of finalized blocks is treated as a single block, with the
tail block's hash representing the entire group.
```

**File:** processor/src/signer.rs (L289-305)
```rust
  pub fn completed(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: [u8; 32],
    completion: &<N::Eventuality as Eventuality>::Completion,
  ) -> Option<ProcessorMessage> {
    let first_completion = !Self::already_completed(txn, id);

    // Save this completion to the DB
    CompletedOnChainDb::complete_on_chain(txn, &id);
    CompletionsDb::complete::<N>(txn, id, completion);

    if first_completion {
      Some(self.complete(id, &N::Eventuality::claim(completion)))
    } else {
      None
    }
```
