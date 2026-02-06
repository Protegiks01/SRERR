### Title
Unauthenticated Network Connection Allows Denial of Service via Malformed Signature Data in Message Queue Service

### Summary
The message queue service, which provides critical inter-service communication for validator operations, accepts unauthenticated TCP connections on port 2287 and calls `.unwrap()` on `SchnorrSignature::read()` before validating signatures. An attacker can send malformed signature data to crash the message queue service, disrupting validator coordination and preventing validators from performing their duties.

### Finding Description

The vulnerability exists in the message queue service at two locations where `SchnorrSignature::read()` is called with `.unwrap()`: [1](#0-0) [2](#0-1) 

The root cause is that the message queue service binds to an unauthenticated network port: [3](#0-2) 

Note the TODO comment indicating connection-level authentication is not implemented. The service accepts TCP connections from anyone and immediately processes messages without authenticating the connection.

While `SchnorrSignature::read()` properly returns `io::Result` and handles EOF/malformed input without panicking: [4](#0-3) 

The underlying `C::read_G()` and `C::read_F()` methods correctly return errors for malformed data: [5](#0-4) [6](#0-5) 

However, the `.unwrap()` calls in the message queue panic when `read()` returns an error. This occurs BEFORE signature verification, which happens later in `queue_message()`: [7](#0-6) 

### Impact Explanation

The message queue service is critical validator infrastructure that enables communication between the coordinator and processor services. According to the architecture documentation, these services must coordinate for:
- Scanning external blockchain deposits
- Coordinating FROST threshold signatures
- Publishing batches to the Serai chain

Crashing the message queue service prevents validators from:
1. Receiving deposit notifications from processors
2. Coordinating multi-party signing operations
3. Publishing signed batches to the Serai blockchain

This effectively disables the validator's cross-chain functionality until the service is manually restarted. Multiple validators could be targeted simultaneously to disrupt the entire network's cross-chain operations.

While this is classified as "Low" in the Protocol Scope ("Undocumented panic reachable from a public API"), the MEDIUM severity is justified because the affected service is critical infrastructure that validators must run to fulfill their duties.

### Likelihood Explanation

**Attack Prerequisites:**
- Network connectivity to the message queue port (2287) on any validator
- Ability to send TCP packets (no authentication required)

**Attack Complexity:**
- Trivial: Connect to port 2287 and send a malformed MessageQueueRequest with invalid signature bytes (wrong length, non-canonical encoding, invalid point data, etc.)

**Economic Feasibility:**
- Zero cost: No staking, transaction fees, or computational expense required
- Can be automated to continuously target multiple validators

**Detection Risk:**
- Low: Appears as a normal crash in validator logs
- No on-chain evidence of the attack
- Difficult to distinguish from legitimate crashes

The attack is extremely practical with minimal barriers to execution.

### Recommendation

Replace `.unwrap()` calls with proper error handling. The signature verification already happens in `queue_message()` and will reject invalid signatures, so malformed data should simply be logged and the connection should be closed gracefully.

**Specific code changes:**

In `message-queue/src/main.rs`, replace lines 243-249:
```rust
MessageQueueRequest::Queue { meta, msg, sig } => {
  let Ok(signature) = SchnorrSignature::<Ristretto>::read(&mut sig.as_slice()) else {
    log::warn!("Received malformed signature in Queue request");
    break;
  };
  queue_message(&mut db, &meta, msg, signature);
  let Ok(()) = socket.write_all(&[1]).await else { break };
}
```

Apply the same pattern to lines 264-270 for the Ack request.

**Additional mitigations:**
1. Implement connection-level authentication as noted in the TODO comment
2. Add rate limiting to prevent rapid repeated attacks
3. Consider using TLS with client certificates for mutual authentication

**Testing recommendations:**
- Create integration tests that send malformed signature data to the message queue
- Verify graceful error handling without panics
- Test with various malformed inputs: wrong lengths, non-canonical encodings, invalid points

### Proof of Concept

**Exploitation steps:**

1. Construct a malformed MessageQueueRequest::Queue with invalid signature data:
   - Set `sig` to a byte array that will fail deserialization (e.g., all zeros, wrong length like 32 bytes instead of 64, or bytes that encode a non-canonical scalar)

2. Connect to the message queue service:
   ```
   nc <validator-ip> 2287
   ```

3. Send the malformed request:
   - Encode the MessageQueueRequest using borsh serialization
   - Prepend with length as u32 (little-endian)
   - Send over the TCP connection

4. Observe the message queue service crash with a panic

**Expected behavior:**
The service should reject the malformed signature gracefully and close the connection, logging an error.

**Actual behavior:**
The service panics at the `.unwrap()` call when `SchnorrSignature::read()` returns an error, terminating the process.

**Realistic parameter values:**
- `sig` = `[0u8; 32]` (wrong length, should be 64)
- `sig` = `[0xffu8; 64]` (likely non-canonical scalar encoding)
- `sig` = A 64-byte array where the first 32 bytes don't decode to a valid Ristretto point

Any of these will cause `read()` to return an error, triggering the panic.

### Citations

**File:** message-queue/src/main.rs (L67-70)
```rust
    let from = KEYS.read().unwrap()[&meta.from];
    assert!(
      sig.verify(from, message_challenge(meta.from, from, meta.to, &meta.intent, &msg, sig.R))
    );
```

**File:** message-queue/src/main.rs (L230-240)
```rust
  let server = TcpListener::bind("0.0.0.0:2287").await.unwrap();

  loop {
    let (mut socket, _) = server.accept().await.unwrap();
    // TODO: Add a magic value with a key at the start of the connection to make this authed
    let mut db = db.clone();
    tokio::spawn(async move {
      while let Ok(msg_len) = socket.read_u32_le().await {
        let mut buf = vec![0; usize::try_from(msg_len).unwrap()];
        let Ok(_) = socket.read_exact(&mut buf).await else { break };
        let msg = borsh::from_slice(&buf).unwrap();
```

**File:** message-queue/src/main.rs (L243-249)
```rust
          MessageQueueRequest::Queue { meta, msg, sig } => {
            queue_message(
              &mut db,
              &meta,
              msg,
              SchnorrSignature::<Ristretto>::read(&mut sig.as_slice()).unwrap(),
            );
```

**File:** message-queue/src/main.rs (L264-270)
```rust
          MessageQueueRequest::Ack { from, to, id, sig } => {
            ack_message(
              from,
              to,
              id,
              SchnorrSignature::<Ristretto>::read(&mut sig.as_slice()).unwrap(),
            );
```

**File:** crypto/schnorr/src/lib.rs (L51-53)
```rust
  pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    Ok(SchnorrSignature { R: C::read_G(reader)?, s: C::read_F(reader)? })
  }
```

**File:** crypto/ciphersuite/src/lib.rs (L74-83)
```rust
  fn read_F<R: Read>(reader: &mut R) -> io::Result<Self::F> {
    let mut encoding = <Self::F as PrimeField>::Repr::default();
    reader.read_exact(encoding.as_mut())?;

    // ff mandates this is canonical
    let res = Option::<Self::F>::from(Self::F::from_repr(encoding))
      .ok_or_else(|| io::Error::other("non-canonical scalar"));
    encoding.as_mut().zeroize();
    res
  }
```

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
