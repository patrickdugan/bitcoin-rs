---
BIP: TBD
Layer: Applications
Title: Canonical Proof Authority and Deterministic Push Transitions
Authors: Research draft prepared for Patrick Dugan / Spiral BIPSpace
Status: Research draft, unsubmitted
Type: Specification
Created: 2026-11-13
Version: 0.0.1
License: BSD-3-Clause
Requires: 341, 342, Keyless-CHECKSIG (unassigned companion proposal)
Conditional dependencies: 347 for CAT-based verifier implementations; 360 for the P2MR profile
---

# Canonical Proof Authority and Deterministic Push Transitions

## Abstract

Canonical Proof Authority (CPA) assigns a reproducible identity to a program and the rules under which proofs of that program authorize Bitcoin transactions. A canonical descriptor commits to the program, its proof-verification machinery, and its interfaces. A state commitment specializes that authority into a locking script. Funding creates a UTXO governed by the already-defined authority.

A spending proof establishes an authorized transition and binds its result to the actual transaction through the proposed Keyless CHECKSIG `TXCOMMIT` check. The transition determines an ordered set of outputs, including any successor authority. Delegation permits another bounded proof relation to supply authorization while retaining the parent authority's restrictions on the specific transaction.

The informal name **platonic address machine** describes this correspondence: an authority's address can be computed from its committed definition before anybody funds it. A program's identity is shared by every exact copy. Bitcoin continues to track separately funded coins through their outpoints.

This document specifies an application protocol over separately activated consensus primitives. It allocates no opcode, witness version, signature-key selector, or general-purpose native proof verifier. The accompanying model tests commitment derivation only. A production verifier profile remains to be implemented and measured. **Never fund the research outputs in this package.**

## Motivation and prior art

The existing Keyless CHECKSIG proposal makes a script-validated transaction digest enforceable against the real spending transaction. CPA specifies the authority that supplies that digest, its canonical address derivation, and the conditions under which embedded verifier logic may accept a delegate. The examined companion draft fixes `SIGHASH_DEFAULT` and uses a research-only unknown-key selector. [KCS]

Ethereum already provides deterministic creation through CREATE2, whose address formula includes a deployer, salt, and initialization-code hash. Its account-abstraction standards also support programmable authorization and delegation. CPA adopts a mandatory content-derived namespace for its descriptors and state commitments. This is a protocol design choice; equivalent application conventions can be built on other programmable ledgers. Claims of greater computational expressiveness are outside this proposal. [E1014, E4337, E7702]

Simplicity's commitment Merkle roots supply a particularly close precedent for identifying program structure. CPA builds on the same general content-addressing idea and specifies an additional transaction-bound, proof-delegation discipline for the Keyless CHECKSIG setting. [SIM]

An ordinary BitVM challenge protocol and the direct-validity profile here have different acceptance conditions. CPA's direct-validity profile requires the locking script to verify its authorization proof before a payout succeeds. An optimistic profile would need a separately identified dispute state machine and explicit challenge assumptions. [BITVM2]

## Scope and terminology

An **authority descriptor** fixes the immutable interpretation of authorization. Its 32-byte hash is the **AuthorityID**, written `A`. The **ProgramID**, written `P`, identifies the normalized gate structure and interface. A **state root**, written `s`, commits to mutable application state under the descriptor's state ABI. A **coin** is a UTXO paying the script derived from `(A, s)`, identified by its actual outpoint.

These identifiers answer separate questions. `P` identifies a circuit. `A` identifies the circuit together with its verifier and policy interpretation. The pair `(A, s)` determines a receiving script, while the outpoint identifies a particular spendable coin.

CPA canonicality covers the explicitly specified normalization rules. Arbitrary circuits that compute the same Boolean function can retain different ProgramIDs. A proof of equivalence can support an authorized migration between them.

The key words MUST, MUST NOT, REQUIRED, SHOULD, and MAY state requirements for CPA implementations. An application-level MUST becomes enforceable on coins only through the actual committed locking program. Wallet labels and descriptor metadata cannot impose conditions missing from that program.

## 1. Hashing and serialization

All CPA hashes are 32-byte SHA256 tagged hashes:

```
TH(tag, message) = SHA256(SHA256(ASCII(tag)) || SHA256(ASCII(tag)) || message)
```

CPA tags begin with `CPA/v0/`. Fixed-width integers use unsigned little-endian encoding. Variable-length collections use Bitcoin CompactSize with the shortest valid representation. Decoders MUST reject trailing data, unknown versions, and noncanonical encodings. An implementation MUST reject an unknown profile instead of assigning it default semantics.

The descriptor is exactly 290 bytes: a two-byte version `0x0000`, followed by nine 32-byte fields in this order.

| Field | Meaning |
|---|---|
| `network_domain` | Identifies the intended chain context under the selected execution profile. |
| `semantics_id` | Pins the circuit language and input/output interpretation. |
| `program_id` | Commits to the normalized transition program. |
| `execution_profile` | Pins the output type and active Script/TXCOMMIT rules. |
| `verifier_suite_id` | Pins the proof system, transcript, parameters, and verifier semantics. |
| `verifier_body_hash` | Commits to the exact parametric Script verifier body. |
| `statement_abi_id` | Pins transaction, request, state, and public-input encodings. |
| `delegation_policy_id` | Pins the rules for grants, retained guards, and revocation. |
| `resource_profile_id` | Pins application proof and execution bounds. |

```
A = TH("CPA/v0/Authority", descriptor_bytes)
body_hash = TH("CPA/v0/VerifierBody", B)
s = TH("CPA/v0/State", canonical_state_bytes)
```

An execution profile MUST define `network_domain` in full, including byte order and any genesis/checkpoint conventions. A chain label supplies domain separation between different labels. Forks sharing that label and a common UTXO history require an additional authenticated fork distinction when replay protection is desired.

Human names, deployer addresses, source-code comments, and arbitrary deployment salts have no field in this descriptor. Application parameters that change authorization belong in committed program inputs or state. A changed verifier body changes `A` even when `P` stays constant.

## 2. Gate-derived program identity

The reference fingerprint grammar is a finite, acyclic Boolean graph with ordered external inputs and outputs. Node types are `INPUT(i)`, `CONST(b)`, and `NAND(x, y)`. External input indices carry their declared semantic positions; local node names carry no meaning.

```
h(INPUT(i))  = TH("CPA/v0/Input", u32(i))
h(CONST(b))  = TH("CPA/v0/Const", byte(b))
h(NAND(x,y)) = TH("CPA/v0/NAND", min(h(x),h(y)) || max(h(x),h(y)))
```

`b` MUST be 0 or 1. Input indices MUST fall within the declared input arity. Children MUST resolve to a finite DAG. Hash-identical structural subexpressions are merged. Unreachable node declarations are rejected. The ordering of outputs remains significant.

For the reference grammar:

```
semantics_id = TH("CPA/v0/Semantics", ASCII("bool-nand-dag-v0"))
header = u16(0) || semantics_id || u32(input_count) || CompactSize(output_count)
P = TH("CPA/v0/Program", header || output_node_hashes_in_order)
```

A canonical full encoding appends the distinct reachable node count and each node record. Records are sorted by `(height, node_hash)`; input and constant nodes have height zero, and a NAND node has one plus its greatest child height. Records use tags `0x00`, `0x01`, and `0x02`, followed respectively by a four-byte input index, a one-byte constant, or two sorted child hashes. A decoder recomputes the hashes and checks the ordering.

This normalization gives equal identities after local gate renaming, NAND-operand swapping, serialization reordering, or duplication of an identical subexpression. It preserves distinctions between unrelated Boolean rewrites. Collision resistance underlies the identification of a hash with its structure.

A practical VM profile MAY use another fully specified canonical intermediate representation. That changes `semantics_id`. Every proof backend MUST demonstrate how its verified computation binds to `P`; hashing a circuit next to an unrelated verifying key is insufficient.

## 3. Canonical locking template

Let `B` be a parametric Tapscript verifier body whose exact bytes hash to the descriptor's `verifier_body_hash`. The body receives the public authority and state from the locking script, with proof material and the candidate transaction digest supplied in the witness.

The normative template is:

```
PUSH32(A)
PUSH32(s)
B
PUSH33(TXCOMMIT_KEY)
OP_CHECKSIGVERIFY
OP_TRUE
```

All pushes shown here use their minimal encoding. On successful verification, `B` MUST consume the witness and the two constants and leave exactly one 32-byte candidate digest `d`. Every failed check MUST abort. The final two opcodes implement the companion proposal's comparison with the real transaction.

A verifier profile MUST specify the exact stack ABI and full bytecode of `B`. It MUST require balanced conditionals, prohibit `OP_CODESEPARATOR`, and exclude every still-undefined `OP_SUCCESSx`, unknown leaf version, and unapproved signature-key type. The fixed suffix MUST execute on every successful path. This restriction prevents an undefined-success instruction from bypassing the verifier. [342]

`B` is parametric in `A` and `s`; it contains neither its own AuthorityID nor a hard-coded future transaction digest. The descriptor may therefore commit to `B` without a hash fixed point. The successor state is introduced by the next locking template.

### 3.1 Script-only P2MR profile

The primary script-only profile uses the proposed BIP360 output. Its tree has exactly two leaves: the authority script `L`, and the one-byte script `0x6a` (`OP_RETURN`).

```
l = TapLeaf(0xc0, L)
u = TapLeaf(0xc0, 0x6a)
m = TapBranch(min(l,u), max(l,u))
scriptPubKey = 0x52 || 0x20 || m
```

The `TapBranch` expression denotes the usual tagged hash of the sorted pair. A human-readable address follows the corresponding witness-address encoding for the selected network. The identity primarily specifies the scriptPubKey bytes.

The examined BIP360 v0.12.1 treats depth-zero trees as anyone-can-spend, so the failing sibling is mandatory here. Its depth-one control block is `0xc1 || u`. This profile has no elliptic-curve key path. Changes to the companion draft require a distinct execution profile. [360]

### 3.2 P2TR research comparison

A separate P2TR profile can commit the same kind of tree using a fixed, auditable NUMS internal point and the ordinary TapTweak construction. Its security retains the elliptic-curve assumption associated with that key path. The scalar `H(circuit)` MUST NOT be used as a secret signing key: the circuit makes that value publicly computable. [341]

The script-only P2MR profile is the target for authority without a key-path escape. Neither profile provides a hidden secret merely by hashing public gates.

## 4. Proof statement and actual-transaction binding

The outer proof statement is the following fixed 96-byte value:

```
X = A || s || d
```

The verifier suite fixes its transcript domain and the conversion between these bytes and any proof-system field elements. Splitting, packing, and range checks MUST be injective; reducing arbitrary 256-bit values modulo a smaller field is forbidden as a statement encoding.

The authorization relation `R_CPA(X; w)` MUST establish all of the following conditions within the checked proof, or through equivalent checks in `B`.

**Descriptor and program binding.** The opened descriptor hashes to `A`. The executed program has the committed `P`, and the semantics and resource profiles match the descriptor. Verification parameters and any application-specific verifying key are authenticated under `verifier_suite_id`. The actual transition relation includes the delegation policy's retained guards.

**Current state.** The opened state hashes to `s`. The selected spending input identifies the actual coin. Each authenticated request input has the provenance required by the policy. A witness assertion about a ledger event or credential requires the corresponding proof.

**Transition.** Evaluating the committed finite computation on the state and authenticated request produces an action record. That record fixes the ordered payout outputs and successor state commitments, and specifies every allowed fee or auxiliary output. For fixed complete semantic inputs, the action record is deterministic.

**Transaction reconstruction.** The proof reconstructs the BIP341 signature message from a supplied transaction and the necessary spent-output data. It derives each relevant output script from the action record and matches its exact value and output index. It reconstructs the current leaf from `(A, s, B)` and checks the current spent scriptPubKey under the selected output profile. [341]

**Digest.** The reconstructed digest equals the public `d`, using the companion TXCOMMIT domain, `SIGHASH_DEFAULT`, script-path extension, no annex for this profile, and `codesep_pos = 0xffffffff`. The concluding CHECKSIGVERIFY then compares `d` to the digest computed from consensus's actual transaction context. [KCS]

The exact locking bytes and the proof statement must meet at this final check. A proof that merely establishes some computation, some recipient, or an unrelated hash fails the CPA relation.

A statement's digest may be computed after funding. Its inputs then include the real outpoint and current leaf hash. Keeping the outpoint out of the pre-funding descriptor avoids the circularity of committing a complete future spending digest into the output that helps determine that digest.

## 5. Deterministic push authority

Write the authorized transition as:

```
F_D(state, authenticated_request, private_witness) -> action_record
```

The action record contains an ordered list of outputs. Each entry names a value and a destination form. An authority destination supplies a child descriptor and state opening, from which the script is derived exactly. A conventional payout supplies an explicitly authorized scriptPubKey. The program checks which forms are allowed.

Given those inputs and the explicit fee choices permitted by the policy, a valid proof determines where value goes. Any party capable of constructing the proof and transaction can relay it. Transaction creation, fee payment, and miner inclusion still require participants; Bitcoin validation does not initiate transactions when a predicate becomes true.

Each successor descriptor MUST be authenticated by the parent relation. Every output, including change or a relayer payment, MUST appear in the action record or be admitted by a precisely specified rule. A permissive extra-output rule can move the entire economic authorization outside the intended policy.

Full-transaction binding means adding a sponsor input, changing a fee, or reordering an output changes the proof-bound transaction digest. A profile must account for reproving and fee management. A pre-authorized fee output can support a separate child transaction where standard policy permits it; this remains an application and relay-policy consideration.

## 6. Delegation through embedded verifier relations

The default mode is **in-place delegation**: the parent coin stays governed by its original descriptor, and an embedded child verifier supplies a bounded part of the authorization for spending it.

A grant commits to the parent authority, the child relation and verifier parameters, a capability scope, and state-dependent validity data. Its canonical format MUST include a unique grant identifier and an epoch or other freshness mechanism supported by the parent state. The grant's presence must follow from the parent's committed grant registry or an explicitly authorized grant transition.

For a concrete transaction statement `X`, acceptance has the form:

```
ParentGuard(state, request, action_record)
AND AuthorizedGrant(state, grant)
AND ScopeAccepts(grant.scope, state, request, action_record)
AND VerifyChild(child_id, child_statement(X, grant), child_proof)
AND ApplyGrantStateUpdates(state, action_record)
```

The parent guard is checked for the same action record committed by `d`. Child proofs bind the parent `A`, current state root, grant identifier, and transaction digest. Rebinding a valid child proof to another parent or transaction MUST fail.

Every level of an allowed delegation chain MUST check its retained guard on the actual transition. This gives a useful containment property:

```
accepted_transitions(parent with delegation)
    subset_of transitions admitted by ParentGuard
```

The property follows because every accepted delegated transition still satisfies that conjunct. ParentGuard must cover the economic restrictions that the parent intends to retain. A local guard can be insufficient for a cross-transaction allowance; such a limit also requires authenticated state updates.

The core profile checks the concrete proposed action at each level. A profile that accepts a proof of universal refinement between arbitrary programs must separately define the proof calculus and resource bounds for that stronger claim.

### 6.1 Arbitrary bounded abstractions

The child can prove a credential policy, or it can prove a transition of a privately executed application. Each abstraction must reduce to a finite, specified acceptance relation and authenticated public inputs. Hidden witnesses may contain private credentials where the selected proof system provides zero knowledge.

External facts need an explicit source of authority. A proof of a message's valid signature establishes that signature relation. A proof about another chain establishes the chosen consensus or checkpoint relation. The parent policy carries the resulting oracle, finality, or trust assumptions.

A child verifier cannot introduce fresh arbitrary executable Script through the witness. The locked verifier checks a proof for an authenticated child relation, or uses a fixed bounded universal verifier. Proof-system parameters supplied by a spender must be derived deterministically or authenticated by a committed hash and suite policy.

### 6.2 Budgets, copying, and revocation

A capability with a cumulative allowance must be tracked in authenticated state and consumed through a serial state transition or an explicitly conserved split. Copying a grant's bytes does not decrement any counter. A profile MUST enforce, for every split, that the sum of child allowances and retained allowance stays within the parent's remaining allowance.

In-place grants can be revoked by a confirmed parent transition that updates the grant registry or epoch. A separate child UTXO requires its own revocation design. Enforcing a changing parent registry from that child generally requires a jointly consumed authenticated control coin or another explicitly supported mechanism. A witness claiming to describe the latest registry is insufficient.

Time rules must use conditions the verifier can authenticate and Script can enforce. A value called `expiry_height` in the witness does not establish the current block height. Upper-bound expiry requires a specified enforceable mechanism. The initial grant format uses state epochs rather than promising generic wall-clock revocation.

### 6.3 Materialized child authorities

A parent transition MAY create a coin at another canonical authority address. This spends value into a child policy and is recorded in the parent's action record. Restrictions intended to survive must be included in the child descriptor and enforced by its verifier. Parent authorization checks the complete derived child address.

Authority transfer and in-place delegation have different revocation behavior. A descriptor MUST identify the selected mode. A materialized child carries any conserved allowance in its own authenticated state.

## 7. Identity, duplication, and linear state

Identical descriptors produce the same `A`. For the same state root, conforming encoders produce the same locking script. This property follows directly from deterministic encoding and hashing.

Anyone may create multiple outputs paying that script. These outputs are distinct coins. A circuit hash supplies no global singleton, shared counter, or globally unique grant token.

Applications needing a single evolving state MUST choose an explicit lineage profile. Such a profile pins a real bootstrap outpoint, authenticates each state coin's ancestry back to it, and permits at most one successor state coin per transition. A copied state label or deposit address cannot establish that ancestry. Genesis initialization must consume the authenticated bootstrap coin under the profile's rules.

An inductive argument then establishes uniqueness among valid descendants: the bootstrap gives one state coin; each accepted transition consumes its predecessor and produces at most one successor; Bitcoin's UTXO rule prevents two confirmed spends of the same predecessor on one chain history. The ancestry verifier must bind the current actual outpoint through creating transactions, including output indices. A label alone does not supply the induction hypothesis.

This package does not implement that lineage verifier. The core descriptor and address model therefore makes no singleton or global-budget guarantee.

A stable AuthorityID can span successive state roots. Each updated `s` changes the state-specific address. Wallets must learn the current state through an authenticated procedure before routing a state-dependent payment. A stable deposit endpoint needs a separately specified inbox policy.

## 8. Recursion and resource bounds

A recursive proof may aggregate a bounded delegation chain or transition history. The accepted proof must terminate in a pinned base case. Cycles that establish authority only by assuming their own validity are forbidden. A profile specifies either a finite depth bound or a well-founded rank together with bounded outer verification.

The resource profile commits to maximum proof size and execution limits, including any recursion/delegation bounds. A deployed verifier profile must state its soundness target and demonstrate it under its named cryptographic assumptions. A numeric security field alone proves nothing.

All on-chain verification must fit the applicable Script and block rules. CAT-based implementations inherit the companion opcode's element-size rule. Declaring a large proof budget in a descriptor cannot expand Bitcoin's limits. [342, 347]

The direct-validity profile requires full acceptance of the payout relation before releasing application value. Splitting a large verifier across transactions requires a separate staged-verification protocol that preserves locked funds and defines recovery from an abandoned sequence. A successful isolated verifier step establishes neither that protocol's liveness nor final payout soundness.

The reference model provides no verification-time, proof-size, or fee estimate. Those quantities require a concrete production verifier and measurements.

## 9. Transparency and privacy

The intended transparent profile uses proof machinery whose public parameters can be derived and audited without a secret setup value. That condition applies throughout the accepted proof stack, including recursive wrappers. Any setup-dependent profile must identify the assumption explicitly and receives a different verifier-suite identity.

Zero knowledge is a separate profile property. The verifier must specify which witness components are hidden and which remain public. Bitcoin transaction values and destination scripts remain visible under this design. Canonical program identities may also make repeated use of a policy recognizable. Hashes of a small set of possible policies provide little hiding by themselves.

The descriptor's authenticated semantics make verifier changes visible in the authority address. An authorized migration can move funds from one suite to another, subject to the old authority's guards. This package defines no invisible verifier-upgrade backdoor.

## 10. Security obligations

A conforming implementation must establish that the deployed bytecode checks the claimed relation. Compiler correctness and correct witness binding are part of that obligation. A self-consistent descriptor can still describe an unsafe policy, and a content hash cannot certify its quality.

Under collision resistance, proof-system soundness, correct compilation, and correct consensus execution of the companion primitives, an accepted direct-validity spend establishes the committed relation for its actual transaction. The reasoning composes three authenticated steps: the output commits to the verifier and state; the verifier accepts `(A,s,d)` only for that relation; TXCOMMIT compares `d` with the actual transaction digest.

Delegation preserves a parent invariant only to the extent that the invariant is present in the retained guard and its state transitions. Aggregate allowances, lineage uniqueness, and revocation require the state mechanisms specified above. Consensus reorganization changes which state transition is current and must be handled by applications.

Open proof submission permits proof copying. Binding the recipient and any authorized relayer payment to `d` prevents a copied proof from redirecting those outputs under the stated assumptions. A public predicate may intentionally allow every participant to produce the same authorized transaction; the payout policy must remain safe under that condition.

## 11. Consensus compatibility and deployment

CPA itself is an application specification. Its script-only target depends on separately activated Keyless CHECKSIG and P2MR semantics. A verifier implemented using CAT also depends on the corresponding activation. It requests no modification to the existing OP_MULADDMOD experiment or the Keyless CHECKSIG implementation PR.

Before an extension activates, an unknown-key selector or undefined-success opcode can have permissive semantics. The research scripts must remain confined to explicitly patched test environments. [342, KCS]

The initial implementation milestone is a complete small transition, with two independently derived copies producing the same script, an enforced retained parent guard, and a child authorization proof bound to that exact spend. The next milestone is an end-to-end transparent verifier for the actual payout relation, measured under node validation and relay constraints.

An accepted BIP number, deployment schedule, mainnet compatibility claim, and production verifier-suite assignment are absent from this research version.

## 12. Test vectors and current implementation

The accompanying `reference.py` supplies the commitment operations and deterministic fixture `vectors.json`. Its demonstration body is `OP_RETURN`, which deliberately rejects every spend under the intended activated rules. The output bytes exist solely for testing identity derivation.

The suite has 28 passing test methods, including parameterized descriptor and statement mutations. It tests gate renaming, NAND input ordering, duplicated-subexpression merging, malformed graphs, separation of descriptor fields, changed state commitments, verifier-body substitution, the exact template suffix, and the depth-one P2MR root/control format.

The tests perform no ZK verification and execute no Bitcoin transaction. They do not test the delegation, lineage, fee, or compiler-correctness obligations described in this draft. An independent implementation remains necessary for differential vector testing.

Run from the directory containing the files:

```sh
python -m unittest -v
python reference.py
```

Future adversarial conformance tests must cover altered output amounts and indices; substituted verifier parameters; grants for another parent; fabricated lineage; overallocated split capabilities; stale epochs; omitted successor commitments; witness-only expiry claims; replay across domains; undefined-success instructions; incorrect field packing; and late verifier failures.

## References

External sources were checked on 2026-11-13. References to drafts describe their examined versions; this document creates no consensus allocation.

[KCS] Spiral, `BIPSpace/Keyless-CHECKSIG/bip-keyless-checksig.md`, inspected content blob `883416ec28399ab7327793be9d438383e7c737d3`. The specification's implementation-status prose may lag subsequent experimental work. Its selector is `0x02 || SHA256("BIPSpace/Keyless-CHECKSIG/TXCOMMIT-draft")`; the research key version is `0x02`.

```text
https://github.com/patrickdugan/Spiral/blob/main/BIPSpace/Keyless-CHECKSIG/bip-keyless-checksig.md
```

[341] BIP341, Taproot output construction and signature-message rules.

```text
https://bips.dev/341/
```

[342] BIP342, Tapscript, including unknown-key and undefined-success behavior.

```text
https://bips.dev/342/
```

[347] BIP347, OP_CAT in Tapscript, version 1.0.0 as examined.

```text
https://bips.dev/347/
```

[360] BIP360, Pay-to-Merkle-Root, draft version 0.12.1 as examined. The depth-zero behavior and control-byte requirement are profile-relevant.

```text
https://bips.dev/360/
```

[E1014] EIP-1014, Skinny CREATE2.

```text
https://eips.ethereum.org/EIPS/eip-1014
```

[E4337] ERC-4337, Account Abstraction Using Alt Mempool.

```text
https://eips.ethereum.org/EIPS/eip-4337
```

[E7702] EIP-7702, Set Code for EOAs.

```text
https://eips.ethereum.org/EIPS/eip-7702
```

[SIM] Blockstream, What is Simplicity?, discussion of commitment Merkle roots; Simplicity documentation, Execution Model.

```text
https://help.blockstream.com/education/development/how-bitcoin-evolves/what-is-simplicity
https://docs.simplicity-lang.org/documentation/execution-model/
```

[BITVM2] BitVM, BitVM 2: Permissionless Verification on Bitcoin.

```text
https://bitvm.org/bitvm2.html
```
