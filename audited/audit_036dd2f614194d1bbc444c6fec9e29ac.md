### Title
Missing Bitcoin Proof-of-Work Validation Enables MITM Block Substitution Attack

### Summary
Serai's Bitcoin RPC integration lacks proof-of-work validation when retrieving blocks, relying solely on hash comparison. A man-in-the-middle attacker controlling RPC connections for ≥67% of validators can provide fabricated Bitcoin blocks with valid hashes but no actual proof-of-work, causing Serai to mint unbacked sriXYZ tokens based on fake deposits, leading to complete loss of solvency.

### Finding Description

**Location**: [1](#0-0) 

The `get_block()` function retrieves Bitcoin blocks from an RPC endpoint and performs only two validations:
1. Deserializes the block data
2. Verifies the computed block hash matches the requested hash [2](#0-1) 

Critically, there is **no proof-of-work validation**. The function never checks that the block header satisfies Bitcoin's difficulty target (i.e., that `SHA256(SHA256(header)) < target`).

The block hash itself comes from `get_block_hash()` which queries the same RPC endpoint: [3](#0-2) 

**Why existing mitigations fail:**

1. **Parent hash validation is incomplete**: The scanner validates parent hashes for sequential blocks [4](#0-3)  but this only applies AFTER the first scanned block. When a validator first activates at a specific block height, there is no parent block stored in the database, so no parent validation occurs.

2. **Threshold signatures provide only partial protection**: Validators sign batches using FROST threshold signatures [5](#0-4)  where the signed message includes the block hash [6](#0-5) . If validators see different blocks, they sign different messages and the signature fails to aggregate. However, if an attacker controls ≥67% of validators' RPC connections (the threshold t = 2n/3 + 1), all compromised validators see the same fake blockchain and successfully produce a valid threshold signature.

3. **No cross-validation or external oracles**: Each validator independently queries its own Bitcoin RPC endpoint with no mechanism to compare block hashes with other validators before signing begins.

### Impact Explanation

**Critical severity - Complete loss of solvency**

An attacker can fabricate Bitcoin deposits to Serai's multisig address, causing Serai to mint sriXYZ tokens without any actual Bitcoin backing. The attacker can then:
1. Withdraw these unbacked tokens to real external assets (Ethereum, Monero, etc.)
2. Swap them for genuine sriXYZ backed by real deposits
3. Drain the actual Bitcoin reserve through legitimate burn operations

This violates Critical Invariant #5: "Mint/burn accounting: minted sriXYZ equals verified external deposits."

**Quantified impact**: 
- Unlimited unbacked minting (attacker controls the fake blockchain)
- Complete drain of all Bitcoin reserves held in multisig
- Cascading insolvency across all integrated networks
- Total loss for legitimate sriXYZ holders

### Likelihood Explanation

**Difficulty: High | Feasibility: Realistic**

**Required attacker capabilities:**
1. Man-in-the-middle position on network traffic between ≥67% of validators and their Bitcoin RPC endpoints
2. Ability to maintain this position from initial key activation through the attack
3. Infrastructure to serve consistent fake Bitcoin blocks to all compromised connections

**Realistic attack vectors:**
- **BGP hijacking**: Target ASNs of hosting providers where validators run
- **DNS poisoning**: Compromise DNS for Bitcoin RPC endpoints if validators use domain names
- **Centralized RPC services**: If multiple validators use the same RPC provider (e.g., Infura-style service), compromising that provider affects many validators simultaneously
- **Hosting provider compromise**: Cloud providers often share network infrastructure
- **Coordinated ISP-level interception**: For geographically concentrated validators

**Economic feasibility**: 
The attack cost (sophisticated network infrastructure compromise) is justified by the potential gain (draining all Bitcoin reserves, potentially millions of dollars).

**Detection risk**: 
Low - the fake blockchain appears valid to compromised validators. Only off-chain comparison with external Bitcoin nodes would detect the attack, which may not happen until after unbacked tokens are minted and withdrawn.

### Recommendation

**Primary fix: Implement proof-of-work validation**

Add Bitcoin difficulty target verification to the block validation logic:

```rust
// In networks/bitcoin/src/rpc.rs, get_block() function:
// After deserializing the block, add:

// 1. Verify proof-of-work
let block_hash = block.block_hash();
if !block.header.validate_pow(&block.header.target()).is_ok() {
    Err(RpcError::InvalidResponse("block does not satisfy proof-of-work requirement"))?;
}

// 2. Verify difficulty target matches expected (query via RPC or track locally)
// Implement difficulty adjustment verification per Bitcoin consensus rules
```

**Additional mitigations:**

1. **Multi-RPC verification**: Query multiple independent Bitcoin nodes and require consensus on block hashes before proceeding with batch creation

2. **Public block explorers**: Cross-check critical blocks against public Bitcoin explorers (blockchain.info, blockchair, etc.) before activation

3. **Delayed activation**: Require validators to verify several hundred blocks of history match public Bitcoin state before beginning to scan for deposits

4. **Checkpoint validation**: Hardcode recent Bitcoin block hashes in the code and verify the chain builds correctly from these checkpoints

**Testing recommendations:**
- Unit tests for PoW verification with valid/invalid blocks
- Integration tests simulating MITM attacks on RPC endpoints
- Fuzz testing with malformed block headers
- Monitor for consensus failures in threshold signing (potential indicator of divergent blockchain views)

### Proof of Concept

**Attack algorithm:**

```
1. Initial Setup (before validator activation):
   - Attacker establishes MITM on ≥67% of validators' connections to Bitcoin RPC
   - Attacker prepares fake Bitcoin blockchain starting from activation block height

2. Activation Phase:
   - Validators call get_block_hash(activation_number) 
   - Attacker intercepts and returns fake_hash_A for activation block
   - Validators call get_block(fake_hash_A)
   - Attacker returns fake block with:
     * header.prev_blockhash = real activation-1 block hash (if needed)
     * Valid merkle root for fake transactions
     * Nonce chosen such that SHA256(SHA256(header)) = fake_hash_A
       (no difficulty requirement, attacker can try 2^32 nonces quickly)
   
   - Validation passes: computed hash = fake_hash_A ✓
   - No PoW check occurs
   - No parent check (first block) [4](#0-3) 

3. Ongoing Attack:
   - For each subsequent block, maintain chain consistency
   - Include fake deposits to Serai multisig address
   - All compromised validators (≥67%) see same fake chain
   
4. Batch Creation and Signing:
   - Compromised validators create batches with fake deposits [7](#0-6) 
   - They sign batch_message(batch) where batch includes fake block hash [6](#0-5) 
   - ≥67% signatures aggregate into valid threshold signature
   - Coordinator publishes signed batch to Serai
   
5. Impact:
   - Serai mints unbacked sriXYZ for fake deposits
   - Attacker withdraws to real assets or swaps for genuine tokens
   - Bitcoin reserves eventually drained through legitimate burns
```

**Expected vs Actual behavior:**

Expected: Only blocks with valid proof-of-work satisfying Bitcoin's difficulty target are accepted

Actual: Any block with a matching hash is accepted, regardless of whether it satisfies proof-of-work requirements

### Citations

**File:** networks/bitcoin/src/rpc.rs (L151-160)
```rust
  pub async fn get_block_hash(&self, number: usize) -> Result<[u8; 32], RpcError> {
    let mut hash = self
      .rpc_call::<BlockHash>("getblockhash", json!([number]))
      .await?
      .as_raw_hash()
      .to_byte_array();
    // bitcoin stores the inner bytes in reverse order.
    hash.reverse();
    Ok(hash)
  }
```

**File:** networks/bitcoin/src/rpc.rs (L172-186)
```rust
  pub async fn get_block(&self, hash: &[u8; 32]) -> Result<Block, RpcError> {
    let hex = self.rpc_call::<String>("getblock", json!([hex::encode(hash), 0])).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex)
      .map_err(|_| RpcError::InvalidResponse("node didn't use hex to encode the block"))?;
    let block: Block = encode::deserialize(&bytes)
      .map_err(|_| RpcError::InvalidResponse("node sent an improperly serialized block"))?;

    let mut block_hash = *block.block_hash().as_raw_hash().as_byte_array();
    block_hash.reverse();
    if hash != &block_hash {
      Err(RpcError::InvalidResponse("node replied with a different block"))?;
    }

    Ok(block)
  }
```

**File:** processor/src/multisigs/scanner.rs (L527-535)
```rust
          if let Some(id) = ScannerDb::<N, D>::block(&db, block_being_scanned.saturating_sub(1)) {
            if id != block.parent() {
              panic!(
                "block {} doesn't build off expected parent {}",
                hex::encode(block_id),
                hex::encode(id),
              );
            }
          }
```

**File:** processor/src/batch_signer.rs (L270-271)
```rust
          let (machine, share) = match machine
            .sign(preprocesses, &batch_message(&self.signable[&id]))
```

**File:** substrate/in-instructions/primitives/src/lib.rs (L139-141)
```rust
pub fn batch_message(batch: &Batch) -> Vec<u8> {
  [b"InInstructions-batch".as_ref(), &batch.encode()].concat()
}
```

**File:** processor/src/multisigs/mod.rs (L980-985)
```rust
        let mut batches = vec![Batch {
          network: N::NETWORK,
          id: batch_id,
          block: BlockHash(block_hash),
          instructions: vec![],
        }];
```
