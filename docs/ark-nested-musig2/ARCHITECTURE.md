# Ark with NestedMuSig2: architecture

This document describes what `tools/ark-nested-musig2` builds, which parts are
real Bitcoin transactions checked by Bitcoin consensus, and which parts are this
repository's own Ark-inspired protocol logic. Results are in
[RESULTS.md](RESULTS.md); the statement format is in
[NOVA_STATEMENT.md](NOVA_STATEMENT.md).

## Scope and isolation

The tool is a separate workspace package at layer 4 of the dependency model,
like `tools/nested-musig2`. It depends on:

- `bitcoin-rs-nested-musig2` for the BIP draft signing operations;
- `bitcoin-rs-script` and `bitcoin-rs-primitives` to run every input of every
  transaction through the node's own interpreter, with standard flags;
- the `bitcoin` crate for transaction templates and BIP341 derivations.

It does not touch consensus, mempool, storage, P2P or RPC code. The node and
Bitcoin Core see its transactions only through public RPC
(`testmempoolaccept`, `sendrawtransaction`, `submitpackage`, `generateblock`,
`submitblock`, `invalidateblock`, `gettxout`). No soft-fork opcode or
experimental consensus branch is involved.

## Ark construction

The protocol follows Arkade's construction and keeps its script templates.
Interoperability is at the script and address level only; the transport,
round protocol and tree transaction format are this repository's own.

| Output | Key path | Script leaves |
| --- | --- | --- |
| Boarding output | BIP341 NUMS point H (no key path) | `<operator> CHECKSIGVERIFY <owner> CHECKSIG`; `<boarding delay> CSV DROP <owner> CHECKSIG` |
| VTXO | NUMS point H | `<operator> CHECKSIGVERIFY <owner> CHECKSIG`; `<exit delay> CSV DROP <owner> CHECKSIG` |
| Batch output and tree node outputs | aggregate of the users below the node plus the operator | `<batch expiry> CSV DROP <operator> CHECKSIG` (single leaf, depth 0) |
| Connector, liquidity, operator wallet | single operator key, BIP86-style tweak | none |

The default VTXO and boarding scripts are byte-identical to
`arkade-os/rust-sdk` `ark-core` at `c786942969dd16f9e94fc165a99a329a39ed183d`
(`Vtxo::new_default`, `BoardingOutput::new`). `tools/ark-nested-musig2/interop`
builds that crate and the CI interop lane compares seven key and delay cases.
The arkd Go server at `fee16a7ba28c3e508c892b07cb7db9028a715f8f` orders the
cooperative leaf owner-first, which gives a different address for the same
keys; this tool follows the Rust SDK.

Differences from Arkade, each a deliberate choice for this node:

| Arkade | This tool | Reason |
| --- | --- | --- |
| Tree and forfeit transactions are version 3 (TRUC), pay zero fee, and carry a P2A anchor for CPFP | Version 2; every tree and forfeit transaction pays its own fee from the value it spends | bitcoin-rs rejects the P2A anchor spend under its standard script flags, so the zero-fee package does not relay through it (RESULTS.md, section 2) |
| Cosigner keys per node are a flat BIP327 aggregate | Flat or nested (`--shape`); nested is the default | The experiment compares the two |
| Operator signs tree nodes with an ephemeral per-round key | The operator key is constant | Simplicity; it does not change the transaction format |
| Connector tree of radix 4 | One connector output per forfeited VTXO on the commitment | Small rounds |
| Off-chain transfers (arkoor) | Transfers happen inside a round | Not implemented |

## Rounds

The operator builds a round as one `ArkTransitionV1` statement. All
transaction templates in it are fixed before any signature exists, because
every input is SegWit and every txid is therefore known.

1. Values are computed bottom-up: a node output holds its children's values
   plus the fee of the tree transaction that spends it.
2. The commitment transaction spends the boarding outputs and one operator
   liquidity output. It creates the batch output, one connector per forfeited
   VTXO, one output per cooperative exit, and operator change.
3. The tree is a binary split of the participant list. The root spends the
   batch output; every tree transaction has one input and two outputs. A
   single-participant range is a VTXO.
4. Each forfeit spends a connector of this round's commitment and an old
   VTXO, and pays the operator.

Signing order per round:

1. Every cosigner (users and operator) decodes the statement, runs the native
   checker on it, and compares it with its own intent: the VTXO amounts it
   receives, the boarding outputs and old VTXOs it gives up, and its
   cooperative exit outputs. Users and the operator also compare every
   funding output with the UTXO that the node reports (`gettxout`): same
   script, same value, at least one confirmation.
2. One NestedMuSig2 session per tree transaction signs its key-path input.
3. The coordinator hands the signed tree to every cosigner, which verifies the
   transactions on its own branches with the bitcoin-rs interpreter.
4. Only after step 3 do users sign their boarding inputs and forfeits. The
   operator signs its liquidity input and connectors.

A user therefore never gives up a boarding output or an old VTXO before it
holds a fully signed exit path for what it receives.

## Signing policy

Two subgroups of users form a node key, with the operator as a third child of
the root:

```
root = KeyAgg(U(left half), U(right half), operator)
U(range) = KeyAgg(U(left half of range), U(right half of range)), a single user's key for one user
```

For four users this is `KeyAgg(KeyAgg(A, B), KeyAgg(C, D), S)`: four signers
in two subgroups plus the operator, with mixed path depths (users at depth 2,
the operator at depth 1). The root receives the BIP341 tweak for the sweep
leaf. Flat shape is `KeyAgg(A, B, C, D, S)`, which is BIP327 MuSig2.

Every leaf occurrence signs with its own nonce. In round 2 the same user owns
both VTXOs, so the tree root aggregates a duplicate key; the session handles it
as two leaves.

The coordinator verifies every partial signature against the honest context
before aggregation, and the final signature against the BIP341 output key.
`traffic.rs` counts one nonce message up, one context message down and one
partial signature up per edge of the aggregation tree.

## Signer processes and nonces

`RoleSigner` holds one key. Secret nonces live only in memory, keyed by a
session identifier that includes the statement digest, the target, the leaf
and the attempt number:

- a nonce is generated only for a target that the validated statement allows,
  for the node's expected aggregate key, with the sighash that the signer
  computes itself;
- the first partial-signature request removes the nonce, whatever the outcome;
- a used session identifier is never accepted again;
- there is no persisted nonce state, so a restarted process has no nonce to
  reuse.

`ark-nm2 signer` runs a `RoleSigner` behind a one-line-per-request JSON
protocol on stdin and stdout. The regtest scenario runs users 2 and 3 this way,
as separate operating-system processes, and kills and restarts one of them
after it releases a nonce.

## Two execution modes

| Mode | What runs | What it establishes |
| --- | --- | --- |
| `native` | The regtest harness submits the committed graph to bitcoin-rs (`--validation-engine native`) and to Bitcoin Core 31.1, mines on bitcoin-rs, mirrors blocks to Core, and compares verdicts and UTXO state | Consensus and policy acceptance by two independent implementations; script validity by the bitcoin-rs interpreter in-process |
| `nova` | `run-ark-nova-mode.py` takes the same statements, exports the Nova witness, proves it with `ark-nova` from `zk-rusto-no-bitcoino`, and verifies through `ark-nm2 verify-proof` | Arithmetic and single-use relations over the committed records; see [NOVA_STATEMENT.md](NOVA_STATEMENT.md) for what it does not cover |

## Files

| Path | Responsibility |
| --- | --- |
| `src/statement.rs` | `ArkTransitionV1` model, canonical encoding, digest, derived scripts |
| `src/statement/check.rs` | Native checker and coverage manifest |
| `src/statement/nova.rs` | Nova witness export and proof-envelope verification |
| `src/round.rs` | Operator round construction, signing orchestration, exits, sweeps |
| `src/client.rs` | Cosigner validation and signing |
| `src/signing.rs` | Sign targets, sighashes, NestedMuSig2 session coordinator |
| `src/remote.rs` | Signer process protocol |
| `src/scenario.rs` | Regtest scenario, adversarial cases, benchmark |
| `scripts/run-ark-nested-musig2-regtest.py` | Two-node regtest harness |
| `scripts/run-ark-nova-mode.py` | Native versus Nova comparison and envelope controls |
| `scripts/run-ark-nested-musig2-testnet4.py` | Testnet4 staging runner |
