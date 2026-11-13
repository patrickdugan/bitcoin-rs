# Canonical Proof Authority: bitcoin-rs integration

Research only. Use a fresh, isolated regtest node. Public-network funding of
these scripts is unsafe. The compiler depends on experimental TXCOMMIT and
OP_CAT semantics. CPA adds no consensus rule and changes no Rust node source.

This is a separate CPA branch based on Keyless CHECKSIG commit
`188e2d78fbb623a12a42772120a2aa4e437905c1`. It does not update the Keyless or
OP_MULADDMOD branches. The draft PR is stacked on the Keyless branch to keep the
CPA diff separate. Do not merge either research proposal for public deployment.

The application proposal is in [the CPA draft](bip-canonical-proof-authority.md).
That document records the pre-integration commitment-model milestone. This guide
owns the implemented bitcoin-rs profile and its measured scope.

## Implemented profile

`scripts/research/canonical_proof_authority.py` preserves the draft's tagged
hashes, 290-byte descriptor, canonical NAND grammar, and address commitments.
It adds strict descriptor decoding and exposes canonical node records for the
compiler. Its P2MR output function remains a commitment-only model.

`scripts/research/cpa_transition.py` compiles the normalized graph into actual
Tapscript. Each distinct reachable gate gets one witness bit. The script checks
canonical bit encodings and every NAND relation. The ordered circuit outputs
mean `(permission, selector)`. Permission must be one. The selector chooses a
fully committed output action.

The native profile supports at most eight declared inputs and 32 declared
nodes, with exactly two outputs. It uses direct Script verification of a
**disclosed trace**. It implements no ZK proof system. Its suite identity is
`TH("CPA/v0/Profile", "disclosed-nand-dag-direct-script-v0")`.

The descriptor binds the circuit and the verifier body. Renaming local gates,
reordering declarations, and swapping NAND operands produce identical compiled
bytes. The payout map and retained guard are embedded in that body. The same
ProgramID can therefore have different AuthorityIDs under different guards.
The compiler provides one fixed profile; it has no witness-selected verifier
or fallback for an unknown suite.

The execution profile is
`TH("CPA/v0/Profile", "nums-p2tr-two-leaf-kcs2-cat-single-input-v0")`.
Its network domain is exactly
`TH("CPA/v0/Profile", "bitcoin-regtest-only")`. This label gives domain
separation for the research profile. It gives no protection between forks that
share that label and UTXO history.

The live output uses the fixed BIP341 NUMS internal point already used by the
Keyless fixture. The tree contains the CPA script and a one-byte `OP_RETURN`
leaf. The 65-byte control block includes that sibling. This retains the P2TR
key-path discrete-log assumption. The node does not implement the draft's
script-only P2MR target.

## Transaction-bound delegation

State bytes are `u64(amount) || u32(epoch) || grant_id`, exactly 44 bytes. The
compiler specializes each finite stage to its state. A grant commits to the
ProgramID, epoch, cap, and ordered action outputs. The locked verifier checks
that exact grant and state opening.

The child statement is:

```text
TH("CPA/v0/ChildStatement", AuthorityID || StateRoot || GrantID || Digest)
```

The proof supplies the statement and the trace. Script verifies the trace,
retains the parent's payout cap, and recomputes the statement for the digest
of the allowed action. The fixed TXCOMMIT suffix compares that digest with the
node's actual transaction context. An identical-address coin has a different
outpoint, so its proof must be rebound.

The disclosed predicate is public. Anyone who satisfies it can construct a
proof. The statement hash provides context binding; it does not authenticate a
private delegate or provide a credential. A cryptographic private-witness
backend remains separate work.

The initial circuit requires both permission inputs to equal one. Its third
input chooses an action. The parent permits a payout of at most 8,000 sats.
A fully valid child trace selecting 9,000 sats is rejected by the parent guard.
The same selection passes a separately funded 9,000-sat-cap authority. This
positive control distinguishes retained-guard rejection from a bad child trace.

The transaction profile fixes one input, version 2, locktime zero, sequence
`0xfffffffd`, all outputs, no annex, key version 2, and no code separator.
Outputs are ordered and every transition pays exactly 2,000 sats in fees.
Witness-provided outpoint, spent-key, and tapleaf context have fixed widths.
A self-consistent false context still fails the native TXCOMMIT comparison.

## Finite push transitions

Two funded copies share the same canonical parent address. Each follows this
checked path:

```text
100,000-sat parent
  -> 7,000-sat payout + 91,000-sat CPA successor + 2,000-sat fee
  -> 89,000-sat final payout + terminal state receipt + 2,000-sat fee
```

The terminal state receipt is a zero-value OP_RETURN output. The two child
transactions select different authorized final recipients. Successor outputs
are derived from complete child descriptors and states before the parent is
compiled. The parent commits to their exact scripts and amounts.

This is a bounded acyclic expansion. A change in the specialized verifier body
changes AuthorityID. It does not implement arbitrary dynamic successor code,
a recursive universal verifier, or an infinite covenant.

Both funded copies can spend independently. The fixture makes no global
singleton or shared allowance claim. Authenticated lineage and grant revocation
across independent UTXOs remain unimplemented. Epoch checks reject stale state
openings; the fixture does not implement a general revocation transaction.

## Run

```sh
python3 scripts/research/cpa_transition.py
python3 -m unittest discover -s scripts/tests -p 'test_cpa*.py' -v
cargo build --locked --jobs 2 --profile quickstart -p bitcoin-rs \
  --no-default-features \
  --features fjall,experimental-keyless-checksig-regtest,experimental-op-cat-regtest
python3 scripts/research/cpa_regtest.py \
  --binary target/quickstart/bitcoin-rs --output /tmp/cpa-run-01 --timeout 180
```

Use a fresh output directory. The runner creates its own temporary data
directory and binds RPC and P2P to loopback. DNS seeds are disabled. It checks
zero peers and verifies every daemon exit. It never uses wallet keys or an
existing node data directory.

The dedicated workflow builds the research executable, runs the offline suite,
and runs the native campaign. It preserves source, executable hash, logs, and
transaction receipts as Actions artifacts. Hosted results must be checked
separately from the local results below.

## Local evidence, November 13, 2026

The CPA suite has **42 passing test methods**, including the draft's 28
commitment tests. Parameterized cases cover every Boolean input combination,
all context fields, noncanonical bits, descriptor decoding, gate substitutions,
retained guards, and exact successor outputs. The independent Script and
sighash oracle are reused from the existing Keyless test owner.

The native campaign confirms **four transitions** and rejects **49 attacks**
at dry-run admission, broadcast admission, and direct block validation. Each
failed block preserves both height and best-block hash. Seven positive
admission controls pass. Restarts at heights 103 and 104 preserve spent-input
state and live outputs. All three daemon exits are zero. Peer count is zero.

The first run exposed an error in the fixture's expected rejection boundary:
re-inserting the exact confirmed transaction encountered `bad-txns-BIP30`.
The fixture now tests that exact boundary separately from a distinct transaction
spending an already consumed input. The latter must fail at missing/spent
inputs. The completed campaigns pass both cases.

This run used the tested native executable from Keyless Actions artifact
`14006830303`, with SHA256:

```text
fe506c638478d173edd267422856b9fb02c8ab424b694b6c81554dce2a48caa6
```

The downloaded archive matched the published SHA256
`5676cc6f044e98b134266c13133f0451339fa371ddb4c3057209847c52d730a4`.
All 1,325 extracted source files and their executable modes reproduced tree
`c9f0f775b4ff5b08376505bb010b63ca731ba726`, which is the pinned Keyless head's
tree. The CPA changes are Python compiler/harness files and documentation;
the reused native executable is identified as a dependency binary. A fresh
Rust build was not run in the local container.

All 68 existing Keyless Python test methods also pass. An earlier local run
reported four preflight failures because the extracted source archive lacked a
Git HEAD, plus a one-second descendant-start timing failure. A local baseline
commit was created for the archive without changing its verified tree. The
complete suite then passed, including the lifecycle test. No inherited test or
production source was altered. Failed-run logs are retained in the evidence
bundle.

The parent script is 932 bytes. The fixture's largest initial proof element
is 44 bytes. These measurements describe this circuit only.

## Ownership and synchronization

The existing native interpreter owns Script acceptance. The CPA compiler
produces ordinary transaction and witness bytes; it adds no validation flag,
cache identity, persistence format, RPC method, or authoritative sync path.
The existing research feature gates and public-network behavior stay unchanged.

The RPC campaign exercises the existing validation and commit boundaries.
It observes SYNC-04 through precise rejection errors and unchanged applied tips.
It observes SYNC-05 through confirmed outputs and clean-restart reads. Those
observations do not replace the synchronization contract's owner tests or its
broader crash and contention campaigns.

The compiler reuses the existing research transaction serializer and stack
builder. The new suite reuses the existing independent interpreter. This keeps
those byte and stack rules at their current owners.

## Remaining implementation work

A transparent ZK suite must verify the same authority/state/transaction relation
under an explicitly pinned verifier and public-input encoding. CPA currently
has no such suite. Script-only P2MR requires its own node integration. Lineage
verification and conserved capability splitting require authenticated state
protocols. Fee flexibility needs a separately committed transaction policy.

The preserved draft and commitment-model code carry the accompanying
[BSD-3-Clause license](canonical-proof-authority-LICENSE).
