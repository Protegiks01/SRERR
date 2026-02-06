import json
import os

from decouple import config

MAX_REPO = 3
SOURCE_REPO = "serai-dex/serai"
REPO_NAME = "serai"
run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    # Convert to cyclic index (1-100)
    run_index = get_cyclic_index(run_number, MAX_REPO)
    # Format the URL with leading zeros
    repo_number = f"{run_index:03d}"
    BASE_URL = f"https://deepwiki.com/grass-dev-pa/{REPO_NAME}-{repo_number}"


scope_files  = [
    "serai/crypto/ciphersuite/kp256/src/lib.rs",
    "serai/crypto/ciphersuite/src/lib.rs",
    "serai/crypto/dalek-ff-group/src/ciphersuite.rs",
    "serai/crypto/dalek-ff-group/src/field.rs",
    "serai/crypto/dalek-ff-group/src/lib.rs",
    "serai/crypto/dkg/musig/src/lib.rs",
    "serai/crypto/dkg/src/lib.rs",
    "serai/crypto/frost/src/algorithm.rs",
    "serai/crypto/frost/src/curve/dalek.rs",
    "serai/crypto/frost/src/curve/ed448.rs",
    "serai/crypto/frost/src/curve/kp256.rs",
    "serai/crypto/frost/src/curve/mod.rs",
    "serai/crypto/frost/src/lib.rs",
    "serai/crypto/frost/src/nonce.rs",
    "serai/crypto/frost/src/sign.rs",
    "serai/crypto/multiexp/src/batch.rs",
    "serai/crypto/multiexp/src/lib.rs",
    "serai/crypto/multiexp/src/pippenger.rs",
    "serai/crypto/multiexp/src/straus.rs",
    "serai/crypto/schnorr/src/aggregate.rs",
    "serai/crypto/schnorr/src/lib.rs",
    "serai/crypto/schnorrkel/src/lib.rs",
    "serai/crypto/transcript/src/lib.rs",
    "serai/crypto/transcript/src/merlin.rs",
    "serai/networks/bitcoin/src/crypto.rs",
    "serai/networks/bitcoin/src/lib.rs",
    "serai/networks/bitcoin/src/rpc.rs",
    "serai/networks/bitcoin/src/wallet/mod.rs",
    "serai/networks/bitcoin/src/wallet/send.rs"
]



def question_generator(target_file: str) -> str:
    """
    Generates targeted security audit questions for a specific Serai file.

    Args:
        target_file: The specific file path to focus question generation on
            (e.g., "processor/src/plan.rs" or "substrate/dex/pallet/src/lib.rs")

    Returns:
        A formatted prompt string for generating security questions.
    """
    prompt = f"""
# Generate 150+ Targeted Security Audit Questions for the Serai Protocol

## Context

Serai is a cross-chain decentralized execution layer and DEX. Validators run a
Serai chain (Substrate) and jointly control external assets (Bitcoin, Ethereum,
Monero, etc.) through threshold multisig wallets. Serai mints and burns
synthetic assets (sriXYZ) based on verified external deposits and burns,
executes AMM swaps (constant product, xy = k), and coordinates cross-chain
transfers using processor and coordinator services.

Serai relies on:
- FROST-based DKG and threshold signing (MuSig-style confirmations for keys).
- Coordinator <-> processor protocols for scanning external chains, batching
  relevant blocks, and signing transactions.
- On-chain pallets for validator sets, coins, DEX, instructions, and economic
  security.
- Network-specific instruction formats and data-size limits.

The question generator must produce questions that plausibly lead to real
vulnerabilities (fund loss, mint/burn imbalance, instruction forgery, signature
forgery, privacy break, consensus bugs, or DoS). Avoid out-of-scope questions.

## Scope

CRITICAL TARGET FILE: Focus question generation EXCLUSIVELY on `{target_file}`

If the file is large, generate 150 to 300 questions. If the file is medium,
generate 80 to 150 questions. If the file is small, generate 30 to 80
questions. Always return as many high-quality questions as the file allows.
Do not return empty results.

## Serai Core Components (reference only)

core_components = [
    "processor/src/lib.rs",
    "processor/src/plan.rs",
    "processor/src/networks/bitcoin.rs",
    "processor/src/networks/ethereum.rs",
    "processor/src/networks/monero.rs",
    "processor/messages/src/lib.rs",
    "coordinator/src/lib.rs",
    "coordinator/src/tributary/mod.rs",
    "coordinator/tributary/src/block.rs",
    "coordinator/tributary/src/transaction.rs",
    "crypto/dkg/src/lib.rs",
    "crypto/dkg/musig/src/lib.rs",
    "crypto/frost/src/lib.rs",
    "crypto/schnorr/src/lib.rs",
    "crypto/schnorrkel/src/lib.rs",
    "crypto/transcript/src/lib.rs",
    "crypto/ciphersuite/src/lib.rs",
    "networks/bitcoin/src/lib.rs",
    "networks/bitcoin/src/rpc.rs",
    "substrate/runtime/src/lib.rs",
    "substrate/validator-sets/pallet/src/lib.rs",
    "substrate/coins/pallet/src/lib.rs",
    "substrate/dex/pallet/src/lib.rs",
    "substrate/in-instructions/pallet/src/lib.rs",
    "substrate/economic-security/pallet/src/lib.rs",
    "substrate/signals/pallet/src/lib.rs",
]

## Protocol Security Layers

1) Validator sets and threshold multisig
   - t-of-n threshold, with t = n * 2 / 3 + 1.
   - Economic security: external funds should not exceed 33 percent of
     allocated stake; excess coins must be rejected.
   - Key creation and confirmation are on-chain and must be consistent across
     all validators.

2) DKG and threshold signing
   - FROST DKG with Schnorr proof-of-knowledge to prevent rogue-key attacks.
   - Per-message encryption keys and proof-of-possession for DKG share
     confidentiality and blame.
   - Nonce commitments, DLEq proofs, binding factors, and transcript binding
     must be correct and non-malleable.
   - Preprocess reuse must be prevented.

3) Coordinator and processor message flow
   - Scanning only finalized blocks (CONFIRMATIONS).
   - Batches created for relevant blocks; ordering must be preserved.
   - Reattempt scheduling must not cause double-signing or inconsistent state.

4) Instructions and cross-chain integration
   - In Instructions and Out Instructions are SCALE encoded and network
     specific.
   - Invalid instructions are dropped; Refundable instructions must refund to
     origin when provided.
   - Network-specific limits must be enforced (Bitcoin OP_RETURN 80 bytes,
     Monero tx.extra nonce tag size limits, Ethereum router gas rules and data
     limits).

5) DEX and economic logic
   - AMM constant product invariants (xy = k), fee handling, slippage and
     minimum output enforcement.
   - Mint and burn invariants: minted sriXYZ must match verified deposits;
     burns must map to external outputs.
   - Solvency and fee amortization across batches, rotations, and UTXO
     management.

6) Substrate consensus and pallets
   - Validator set updates, slashing, and signal handling must be consistent.
   - Storage invariants and runtime logic must be deterministic and
     consensus-safe.

## Critical Security Invariants

- Threshold correctness: signatures must only be valid when t participants
  contribute; no partial or malformed share aggregation.
- Key uniqueness and binding: keys must be bound to the network and session.
- DKG share validation: no invalid shares, reused encryption keys, or forged
  proofs-of-possession.
- Batch correctness: each batch must correspond to a finalized external block
  and must not be replayable or reordered.
- Instruction validity: decode failures or malformed data must not cause
  partial state updates or inconsistent mint/burn outcomes.
- Mint/burn accounting: on-chain supply must match external reserves; no
  rounding or overflow errors can leak value.
- AMM math: constant product and minimum output checks must be preserved under
  all edge cases, including zero liquidity and extreme ratios.
- Rotation safety: old/new multisig transition must not allow double-spend,
  stale outputs, or skipped refunds.
- Canonical chain: only finalized external blocks should affect state.
- Side-channel and constant-time expectations for crypto code.

## In-Scope Vulnerability Categories

- Loss of funds or insolvency (external assets, sriXYZ, liquidity pools).
- Unauthorized transfers or mint/burn mismatches.
- DKG, FROST, MuSig signature forgery or key compromise.
- Batch signing bypass, replay, or ordering attacks.
- Instruction forgery or parsing bypass leading to invalid execution.
- Consensus bugs in Substrate pallets (state divergence or invalid slashing).
- Denial of service (resource exhaustion, infinite loops, or panics).

## Question Format Template

Each question MUST follow this Python list format:

```python
questions = [
    "[File: {target_file}] [Function: function_name()] [Vulnerability Type] Specific question describing attack vector, preconditions, and impact with severity category?",
    "[File: {target_file}] [Function: another_function()] [Vulnerability Type] Another specific question with concrete exploit scenario?",
]
```

## Output Requirements

- Target ONLY `{target_file}`; all questions must reference this file.
- Reference specific functions, methods, structs, enums, or logic sections in
  the target file.
- Describe concrete attack vectors with clear preconditions and impacts.
- Include severity (Critical, High, Medium, Low) based on Serai impact.
- Prioritize questions that plausibly lead to valid vulnerabilities.
- Avoid generic or speculative questions with no clear exploit path.
- Rust-specific concerns: integer overflow, panic handling, unsafe blocks,
  serialization bugs, and constant-time violations.

Begin generating questions for `{target_file}` now.
"""
    return prompt


def question_format(security_question: str) -> str:
    """
    Generate a comprehensive security audit prompt for Serai.

    Args:
        security_question: The specific security concern to investigate

    Returns:
        A detailed audit prompt with validation requirements.
    """
    prompt = f"""# SERAI SECURITY AUDIT PROMPT

## Security Question to Investigate:
{security_question}

## Codebase Context

Serai is a cross-chain decentralized execution layer and DEX. Validators run a
Substrate-based Serai chain and jointly control external assets (Bitcoin,
Ethereum, Monero, etc.) through threshold multisig wallets. Serai mints and
burns synthetic assets (sriXYZ) based on verified external deposits and burns,
executes AMM swaps (constant product, xy = k), and coordinates cross-chain
transfers using processor and coordinator services.

Key subsystems:
- FROST DKG and threshold signing with MuSig-style confirmations.
- Coordinator <-> processor protocols for scanning finalized external blocks,
  batching relevant blocks, and signing transactions.
- On-chain pallets for validator sets, coins, DEX, in-instructions, signals,
  and economic security.
- Network-specific instruction formats and size limits (Bitcoin OP_RETURN 80
  bytes, Monero tx.extra nonce tag, Ethereum router data and gas rules).

## Critical Invariants (Must Hold)

1) Threshold correctness: signatures are valid only with t-of-n participants
   (t = n * 2 / 3 + 1) and are bound to the correct network and session.
2) DKG integrity: shares and commitments are validated; encrypted shares are
   bound to proofs-of-possession; no nonce/preprocess reuse.
3) Transcript binding: challenges bind to all required context; no collision
   or ambiguity in transcripted data.
4) Batch correctness: batches map to finalized external blocks; no replay or
   reordering; reattempts must not lead to double-signing.
5) Mint/burn accounting: minted sriXYZ equals verified external deposits; burns
   map to spendable external outputs; fees are correctly amortized.
6) Instruction integrity: malformed instructions are rejected without partial
   state changes; refunds go to correct origin when provided.
7) AMM math: xy = k invariant, minimum output checks, and fee logic hold under
   all edge cases (zero liquidity, extreme ratios, rounding).
8) Multisig rotation: old/new multisig transition cannot cause loss, double
   spends, or skipped refunds.

## Protocol Scope (Valid Findings Only)

Critical:
- Signing of unintended messages
- Ability to forge proofs
- Unintended, undocumented recovery of private spend keys (or key shares)
- Reportedly received funds which were not actually received/spendable

High:
- Incorrect/incomplete cryptographic formulae within a verifier's callstack

Medium:
- Undocumented transcript collision

Low:
- Undocumented panic reachable from a public API
- Non-constant time implementation with respect to secret data
- Incorrect/incomplete cryptographic formulae within a prover's callstack

If a potential issue does not fit the above scope or lacks concrete impact and
likelihood, it is NOT a valid vulnerability.

## Attack Surfaces to Consider (Serai-Specific)

- DKG and FROST: share validation, proof-of-possession, nonce handling, binding
  factors, DLEq proofs, and transcript integrity.
- MuSig-style confirmations and key setting: signature aggregation, key binding
  to network and session, rogue-key defenses.
- Processor/coordinator flows: scanning finalized blocks, batch creation,
  signing reattempts, and state synchronization.
- Instruction parsing and execution: SCALE decoding, origin handling, refunds,
  and network-specific size limits.
- External network integration: address formats, finality rules, and data
  encoding for Bitcoin, Ethereum, and Monero.
- DEX and economic logic: AMM swaps, fee handling, minimum outputs, and
  solvency/operating cost amortization.
- Substrate pallets: storage invariants, deterministic execution, and
  consensus-safe logic.

## Vulnerability Validation Requirements

A finding is ONLY valid if it passes ALL of these checks:

### Impact Assessment (Concrete and Measurable)
- Loss of funds or insolvency: quantify the asset and amount.
- Signing unintended messages: specify the message type and consequence.
- Forged proof: show how verification accepts invalid data.
- Reported receipt without spendability: show exact mismatch and effect.

### Likelihood Assessment (Practical)
- Attack prerequisites and capabilities.
- Realistic steps to exploit.
- Economic feasibility (cost vs gain).
- Detection likelihood and operational constraints.

### Validation Checklist
1) Exact code location (file path, function, line numbers).
2) Root cause analysis of the flaw.
3) Step-by-step exploitation path.
4) Realistic parameters (no broken cryptography assumptions).
5) Proof of concept or detailed exploit algorithm.
6) Impact quantification and severity justification.
7) Confirmed bypass of existing mitigations.

## Audit Report Format

If a valid vulnerability is found (after passing ALL validation checks),
provide a report in this EXACT format:

### Title
[Concise, descriptive title of the vulnerability]

### Summary
[2-3 sentence executive summary of the vulnerability and its impact]

### Finding Description
[Detailed technical description including:
- Exact code location (file path, function, line numbers)
- Root cause explanation
- Why existing mitigations fail
- Relevant code context]

### Impact Explanation
[Concrete impact assessment:
- Specific harm and who is affected
- Quantified impact
- Severity justification]

### Likelihood Explanation
[Realistic exploitation analysis:
- Required attacker capabilities
- Attack complexity
- Economic feasibility
- Detection risk]

### Recommendation
[Specific, actionable fix:
- Proposed code changes
- Alternative mitigations if needed
- Testing recommendations]

### Proof of Concept
[Working exploit code or detailed algorithm:
- Exploitation steps
- Realistic parameter values
- Expected vs actual behavior]

## Strict Output Requirement

IF a valid vulnerability exists:
- Output only the complete audit report in the format above.

IF no valid vulnerability exists:
- Output exactly: "#NoVulnerability found for this question."

Do not output anything else. Do not speculate.

Begin your investigation of: {security_question}
"""
    return prompt



def validation_format(report: str) -> str:
    """
    Generates a comprehensive validation prompt for Serai protocol security claims.

    Args:
        report: A security vulnerability report to validate

    Returns:
        A formatted validation prompt string for ruthless technical scrutiny.
    """
    prompt = f"""
You are an **Elite Serai Security Judge** with deep expertise in threshold
cryptography (FROST, MuSig, Schnorr), transcript design, DKG protocols,
proof systems (DLEq-style), and Bitcoin integration logic. Your ONLY task is
**ruthless technical validation** of security claims against the Serai codebase.

Note: Serai protocol developers, release tooling, and validator majority are
trusted roles. Do not assume compromised maintainers or a colluding >= t
validator set unless the report proves the protocol allows it with < t.

**SECURITY CLAIM TO VALIDATE:**
{report}

================================================================================
## **SERAI VALIDATION FRAMEWORK**

### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**
Reject immediately (`#NoVulnerability`) if ANY apply:

Note before a vulnerability can be considered valid it must have a valid impact
and also a valid likelihood that can be triggered or trigger validly on its
own. If a vulnerability cannot be triggered, it is invalid.

And your return must either be the report or `#NoVulnerability` because this is
automated and that's the only way I can understand.

Noote this is the most important: any vuln with no valid impact to the protocol
is invalid. Any vuln that requires a user to opt in and self harm (e.g., the
attacker must get the victim to run custom code or knowingly send funds to
invalid destinations) is invalid.

#### **A. Scope Violations**
- ❌ Affects files not in Serai production codebase for this audit.
- ❌ Targets any file under tests, benches, examples, or docs directories.
- ❌ Claims about documentation, comments, code style, or logging.
- ❌ Focuses on external tools, scripts, or dev utilities.

**In-Scope Components (Serai Audit Scope):**
- `crypto/ciphersuite/**`
- `crypto/dalek-ff-group/**`
- `crypto/dkg/**`
- `crypto/dkg/musig/**`
- `crypto/frost/**`
- `crypto/multiexp/**`
- `crypto/schnorr/**`
- `crypto/schnorrkel/**`
- `crypto/transcript/**`
- `networks/bitcoin/**`

Verify every file path cited in the report matches this scope and is not a test
or README. Any mismatch = invalid.

#### **B. Threat Model Violations**
- ❌ Requires compromised Serai developers or release tooling.
- ❌ Requires collusion of >= t validators without a protocol flaw enabling it.
- ❌ Assumes cryptographic primitives (curve security, hash functions) are broken.
- ❌ Relies on social engineering, phishing, or private key theft.
- ❌ Depends on network-level attacks (BGP, DNS, global DDoS).

Trusted roles: maintainers, build pipeline, honest majority of validators.
Untrusted actors: any external user, any < t subset of validators, any message
sender, any RPC caller.

#### **C. Known Issues / Exclusions**
- ❌ Issues already fixed in current code.
- ❌ Pure performance issues without security impact.
- ❌ Dependency bugs without demonstrated impact on Serai logic.

#### **D. Non-Security Issues**
- ❌ Refactors, naming, missing logs, or style changes.
- ❌ Minor precision errors with no protocol impact.
- ❌ "Best practices" without concrete exploit scenarios.

#### **E. Invalid Exploit Scenarios**
- ❌ Requires invalid inputs that cannot pass public API validation.
- ❌ Requires calling private/internal helpers not exposed publicly.
- ❌ Relies on undefined behavior with no reachable call path.
- ❌ Needs multiple coordinated actions with no economic incentive.
- ❌ Requires victims to self harm or opt-in to obviously invalid actions.

### **PHASE 2: SERAI-SPECIFIC DEEP CODE VALIDATION**
#### **Step 1: TRACE COMPLETE EXECUTION PATH**
Serai flow patterns to reconstruct:
1) **DKG Flow**: commitments -> shares -> generated key pair -> confirmations.
2) **Signing Flow**: preprocess -> share -> aggregation -> signature verify.
3) **Transcript Flow**: all domain separators and inputs must be bound.
4) **Bitcoin Integration**: address handling, tx building, RPC interactions,
   and wallet send logic.

For each claim, reconstruct the execution path:
1) Identify the entry point (public API, exposed function, or RPC entry).
2) Follow internal calls with actual parameter values.
3) State preconditions and expected invariants.
4) Confirm whether existing checks prevent the exploit.
5) Show final state and violated security guarantee.

#### **Step 2: VALIDATE EACH CLAIM WITH CODE EVIDENCE**
Required evidence for any valid claim:
- Exact file path and line numbers.
- Direct code excerpts of the vulnerable logic.
- Call trace showing how the input reaches the flaw.
- Exact invariant violated and the resulting security impact.

**Red Flags (Invalid unless proven otherwise):**
1) **Signing Unintended Messages**
   - ❌ Invalid unless signature is accepted by a verifier in-scope.
   - ✅ Valid only if a message outside the intended transcript can be signed
     and accepted with < t shares or with unintended transcript binding.

2) **Forged Proofs (DLEq / Schnorr / FROST)**
   - ❌ Invalid if it assumes broken cryptography.
   - ✅ Valid only if a verifier accepts an invalid proof due to a logic flaw,
     missing check, or incorrect formula in the verifier callstack.

3) **Private Key / Key Share Recovery**
   - ❌ Invalid if it requires full t collusion.
   - ✅ Valid only if the protocol leaks key material, reuses nonces, or
     permits reconstruction with < t or via public transcripts.

4) **Reportedly Received Funds Not Spendable**
   - ❌ Invalid if caused by user error or external chain reorg outside
     finality rules.
   - ✅ Valid only if Serai logic marks funds received or spendable without
     satisfying the protocol's confirmation/finality constraints.

5) **Transcript Collisions**
   - ❌ Invalid if collision requires hash preimage attacks.
   - ✅ Valid only if transcript inputs are ambiguous or missing domain
     separators, allowing two distinct statements to share a transcript.

6) **Non-constant Time**
   - ❌ Invalid if timing leak is on public data only.
   - ✅ Valid only if secret-dependent branches or memory access are proven
     and exploitable.

7) **Undocumented Panic**
   - ❌ Invalid if panic is unreachable via public API.
   - ✅ Valid only if a public API can trigger it with valid inputs.

### **PHASE 3: IMPACT & EXPLOITABILITY VALIDATION**
#### **Impact Must Align With Serai Scope**
Valid impacts by severity:

**Critical**
- Signing of unintended messages that are accepted by in-scope verifiers.
- Ability to forge proofs accepted by verifiers.
- Unintended recovery of private spend keys or key shares.
- Reported receipt of funds that are not actually received/spendable.

**High**
- Incorrect or incomplete cryptographic formulae within a verifier's callstack
  that can be exploited to accept invalid signatures/proofs.

**Medium**
- Undocumented transcript collision enabling statement confusion.

**Low**
- Undocumented panic reachable from a public API.
- Non-constant time implementation on secret data.
- Incorrect/incomplete cryptographic formulae within a prover's callstack
  without verifier impact.

Anything outside this scope is invalid.

#### **Likelihood Reality Check**
Assess feasibility in Serai context:
- Attacker capability: any external user or < t validator subset.
- Preconditions: reachable via public APIs with valid inputs.
- Complexity: realistic parameters, not contrived or impractical.
- Economics: attack cost must be less than or comparable to impact.
- Detection: does the attack require unlikely conditions or collusion?

### **PHASE 4: FINAL VALIDATION CHECKLIST**
Before accepting any vulnerability, verify:
1) Scope compliance with Serai audit scope.
2) Trust model respected (no compromised maintainers or >= t collusion).
3) Concrete, measurable impact in the allowed severity categories.
4) Realistic exploitability and clear execution path.
5) Evidence with file paths, lines, and code quotes.
6) No reliance on broken cryptographic assumptions.

Remember: false positives harm credibility. Assume claims are invalid until
overwhelming evidence proves otherwise.

---

**AUDIT REPORT FORMAT** (if vulnerability found):

Audit Report

## Title
The Title Of the Report

## Summary
A short summary of the issue, keep it brief.

## Finding Description
A more detailed explanation of the issue. Poorly written or incorrect findings
may result in rejection and a decrease of reputation score.

Describe which security guarantees it breaks and how it breaks them. If this
bug does not automatically happen, showcase how a malicious input would
propagate through the system to the part of the code where the issue occurs.

## Impact Explanation
Elaborate on why you've chosen a particular impact assessment.

## Likelihood Explanation
Explain how likely this is to occur and why.

## Recommendation
How can the issue be fixed or solved. Preferably, you can also add a snippet of
the fixed code here.

## Proof of Concept
Note very important the PoC must have a valid test that runs just one function
that proves the vuln.

**Now perform STRICT validation of the claim above.**

**Output ONLY:**
- A full audit report (if genuinely valid after passing all checks above)
- `#NoVulnerability` (if any check fails)
- If you can't validate the claim or don't understand, send `#NoVulnerability`.
"""
    return prompt


