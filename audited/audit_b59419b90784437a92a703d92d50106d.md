### Title
Malicious Bitcoin Node Can Prevent Transaction Broadcast via Error Code -27 Spoofing

### Summary
A malicious Bitcoin node can return error code -27 (RPC_VERIFY_ALREADY_IN_CHAIN) for transactions that were never broadcast, causing Serai validators to believe a transaction was successfully published when it was not. This breaks the critical invariant that burns map to spendable external outputs, resulting in users losing funds when attempting to withdraw Bitcoin from Serai.

### Finding Description

**Exact Code Location:** [1](#0-0) 

The `send_raw_transaction()` function unconditionally trusts error code -27 from the Bitcoin node and immediately returns success without verifying the transaction actually exists in the blockchain or mempool.

**Root Cause:**
When a Bitcoin RPC call to `sendrawtransaction` returns error code -27 (RPC_VERIFY_ALREADY_IN_CHAIN), the implementation assumes this means the transaction is already successfully published and returns `Ok(tx.compute_txid())`. However, a malicious Bitcoin node can lie by returning this error code for transactions that were never broadcast to the network.

**Why Existing Mitigations Fail:**

1. **Scanner Verification**: The Scanner independently checks for transaction completion on-chain [2](#0-1) , but if the transaction was never broadcast, it will never be found in any block. The transaction remains in `ActiveSignsDb` indefinitely.

2. **Confirm Completion**: When other validators receive the completion claim [3](#0-2) , they call `confirm_completion` which attempts to retrieve the transaction [4](#0-3) . Honest validators with honest Bitcoin nodes will fail this check, but this only logs a warning and does not trigger remediation or slashing.

3. **Rebroadcast Task**: The rebroadcast mechanism [5](#0-4)  keeps republishing the completion, but if it continues hitting the malicious node, it will keep receiving -27 and "succeeding" without actual broadcast.

4. **Reattempt Mechanism**: Reattempts are blocked because the completion was already saved to `CompletionsDb` [6](#0-5)  before `publish_completion` was called, causing `already_completed` to return true [7](#0-6) .

### Impact Explanation

**Affected Users:** Any user attempting to withdraw Bitcoin from Serai by burning sriXYZ tokens.

**Quantified Impact:**
- User burns sriXYZ tokens on Serai (tokens are destroyed)
- Validators sign a Bitcoin transaction to send the withdrawal
- Malicious node prevents broadcast via -27 spoofing
- Bitcoin transaction never executes on Bitcoin network
- User loses funds equal to burned sriXYZ amount
- Funds remain locked in multisig, creating accounting mismatch

**Severity Justification:** HIGH - This directly violates Critical Invariant #5: "burns map to spendable external outputs; fees are correctly amortized." It causes permanent loss of user funds and breaks the fundamental bridge functionality between Serai and Bitcoin.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control or compromise a Bitcoin node that Serai validators connect to
- Ability to intercept and modify RPC responses to return error code -27

**Attack Complexity:**
- LOW to MEDIUM - Requires running a malicious Bitcoin node or compromising an existing one
- If validators use shared Bitcoin infrastructure (common in production), a single compromised node affects multiple validators
- No cryptographic breaking required

**Economic Feasibility:**
- HIGH incentive - Attacker can cause loss of all withdrawal amounts
- Could be combined with shorting sriXYZ or exploiting liquidity pools
- LOW cost if attacker already operates validator infrastructure

**Detection Risk:**
- MEDIUM to HIGH - The attack is detectable because transactions never appear on Bitcoin blockchain
- However, validators may not immediately realize the issue as the system reports success
- Users would notice failed withdrawals, but attribution to this specific cause requires investigation

### Recommendation

**Primary Fix:**
Add verification that the transaction actually exists before returning success on -27 errors. When error code -27 is received, call `get_transaction` to confirm the transaction is genuinely in the mempool or blockchain:

```rust
if code == RPC_VERIFY_ALREADY_IN_CHAIN {
  // Verify the transaction actually exists before trusting the error code
  match self.rpc_call::<String>("getrawtransaction", json!([tx.compute_txid()])).await {
    Ok(_) => return Ok(tx.compute_txid()),
    Err(_) => {
      // Transaction doesn't exist despite -27 claim - treat as broadcast failure
      Err(e)?
    }
  }
}
```

**Alternative Mitigation:**
- Implement multiple Bitcoin node redundancy with cross-validation
- Add slashing for validators whose completions cannot be confirmed by majority
- Implement a timeout mechanism where unconfirmed completions trigger emergency re-signing

**Testing Recommendations:**
- Create integration test with mock Bitcoin node returning -27 for non-existent transactions
- Verify that modified code correctly rejects spoofed -27 errors
- Test that legitimate -27 errors (transaction already in mempool) still succeed

### Proof of Concept

**Attack Algorithm:**

1. **Setup:** Attacker runs malicious Bitcoin node that Serai validators connect to

2. **Wait for Signing:** User initiates Bitcoin withdrawal, validators create and sign transaction with txid `T`

3. **Intercept Broadcast:** When validator calls `sendrawtransaction` with transaction `T`:
   ```
   Malicious node responds: {"error": {"code": -27, "message": "already in chain"}}
   ```

4. **False Success:** Validator's `send_raw_transaction` returns `Ok(T)` at line 198

5. **Completion Claimed:** Validator calls `publish_completion` which succeeds [8](#0-7) 

6. **Coordinator Notified:** Validator sends `ProcessorMessage::Completed` to coordinator

7. **State Locked:** Completion saved to `CompletionsDb`, preventing reattempts

8. **Perpetual Failure:** 
   - Rebroadcast task keeps hitting malicious node, receiving -27
   - Scanner never finds transaction on-chain
   - Transaction never executes
   - User funds permanently lost

**Expected Behavior:** Transaction broadcast fails or retries until successful

**Actual Behavior:** System believes broadcast succeeded, no remediation occurs, user funds lost

### Citations

**File:** networks/bitcoin/src/rpc.rs (L196-199)
```rust
        if let RpcError::RequestError(Error { code, .. }) = e {
          if code == RPC_VERIFY_ALREADY_IN_CHAIN {
            return Ok(tx.compute_txid());
          }
```

**File:** processor/src/multisigs/scanner.rs (L569-590)
```rust
          for (id, (block_number, tx, completion)) in network
            .get_eventuality_completions(scanner.eventualities.get_mut(&key_vec).unwrap(), &block)
            .await
          {
            info!(
              "eventuality {} resolved by {}, as found on chain",
              hex::encode(id),
              hex::encode(tx.as_ref())
            );

            completion_block_numbers.push(block_number);
            // This must be before the mission of ScannerEvent::Block, per commentary in mod.rs
            if !scanner.emit(ScannerEvent::Completed(
              key_vec.clone(),
              block_number,
              id,
              tx,
              completion,
            )) {
              return;
            }
          }
```

**File:** processor/src/signer.rs (L188-205)
```rust
  /// Rebroadcast already signed TXs which haven't had their completions mined into a sufficiently
  /// confirmed block.
  pub async fn rebroadcast_task(db: D, network: N) {
    log::info!("rebroadcasting transactions for plans whose completions yet to be confirmed...");
    loop {
      for active in ActiveSignsDb::get(&db).unwrap_or_default() {
        for claim in CompletionsDb::completions::<N>(&db, active) {
          log::info!("rebroadcasting completion with claim {}", hex::encode(claim.as_ref()));
          // TODO: Don't drop the error entirely. Check for invariants
          let _ =
            network.publish_completion(&CompletionDb::completion::<N>(&db, &claim).unwrap()).await;
        }
      }
      // Only run every five minutes so we aren't frequently loading tens to hundreds of KB from
      // the DB
      tokio::time::sleep(core::time::Duration::from_secs(5 * 60)).await;
    }
  }
```

**File:** processor/src/signer.rs (L254-265)
```rust
  fn already_completed(txn: &mut D::Transaction<'_>, id: [u8; 32]) -> bool {
    if !CompletionsDb::completions::<N>(txn, id).is_empty() {
      debug!(
        "SignTransaction/Reattempt order for {}, which we've already completed signing",
        hex::encode(id)
      );

      true
    } else {
      false
    }
  }
```

**File:** processor/src/signer.rs (L311-362)
```rust
  async fn claimed_eventuality_completion(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: [u8; 32],
    claim: &<N::Eventuality as Eventuality>::Claim,
  ) -> Option<ProcessorMessage> {
    if let Some(eventuality) = EventualityDb::eventuality::<N>(txn, id) {
      match self.network.confirm_completion(&eventuality, claim).await {
        Ok(Some(completion)) => {
          info!(
            "signer eventuality for {} resolved in {}",
            hex::encode(id),
            hex::encode(claim.as_ref())
          );

          let first_completion = !Self::already_completed(txn, id);

          // Save this completion to the DB
          CompletionsDb::complete::<N>(txn, id, &completion);

          if first_completion {
            return Some(self.complete(id, claim));
          }
        }
        Ok(None) => {
          warn!(
            "a validator claimed {} completed {} when it did not",
            hex::encode(claim.as_ref()),
            hex::encode(id),
          );
        }
        Err(_) => {
          // Transaction hasn't hit our mempool/was dropped for a different signature
          // The latter can happen given certain latency conditions/a single malicious signer
          // In the case of a single malicious signer, they can drag multiple honest validators down
          // with them, so we unfortunately can't slash on this case
          warn!(
            "a validator claimed {} completed {} yet we couldn't check that claim",
            hex::encode(claim.as_ref()),
            hex::encode(id),
          );
        }
      }
    } else {
      warn!(
        "informed of completion {} for eventuality {}, when we didn't have that eventuality",
        hex::encode(claim.as_ref()),
        hex::encode(id),
      );
    }
    None
  }
```

**File:** processor/src/signer.rs (L619-619)
```rust
        CompletionsDb::complete::<N>(txn, id.id, &completion);
```

**File:** processor/src/networks/bitcoin.rs (L844-853)
```rust
  async fn publish_completion(&self, tx: &Transaction) -> Result<(), NetworkError> {
    match self.rpc.send_raw_transaction(tx).await {
      Ok(_) => (),
      Err(RpcError::ConnectionError) => Err(NetworkError::ConnectionError)?,
      // TODO: Distinguish already in pool vs double spend (other signing attempt succeeded) vs
      // invalid transaction
      Err(e) => panic!("failed to publish TX {}: {e}", tx.compute_txid()),
    }
    Ok(())
  }
```

**File:** processor/src/networks/bitcoin.rs (L855-863)
```rust
  async fn confirm_completion(
    &self,
    eventuality: &Self::Eventuality,
    _: &EmptyClaim,
  ) -> Result<Option<Transaction>, NetworkError> {
    Ok(Some(
      self.rpc.get_transaction(&eventuality.0).await.map_err(|_| NetworkError::ConnectionError)?,
    ))
  }
```
