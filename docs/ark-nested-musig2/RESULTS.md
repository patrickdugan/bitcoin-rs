# Ark with NestedMuSig2: results

All numbers below were measured on the code in this branch. Machine-readable
data is in `experiments/ark-nested-musig2/results.json`, raw transactions in
`transactions.json`, every adversarial trace in `adversarial-traces.json`, and
pinned sources in `sources.json`.

Where it ran:

- **Local**: WSL2 Ubuntu 24.04 on a 20-thread laptop, Rust 1.99.1,
  bitcoin-rs built with `--profile quickstart --no-default-features --features
  fjall`, Bitcoin Core 31.1 from the pinned tarball.
- **CI**: hosted `ubuntu-24.04` runners, workflow `ark-nested-musig2.yml`
  (conformance, ark-core interop, regtest with benchmark).

Each result says which components actually executed it. Nothing below ran
against a live Arkade or Bark server; the Arkade comparison is at the script
and address level, by executing `ark-core`.

## 1. Lifecycle on bitcoin-rs and Bitcoin Core (native mode)

One four-user Ark lifecycle, plus one refused boarding user, ran as 46 plays
on an isolated bitcoin-rs regtest node and a Bitcoin Core 31.1 node. Every
block was mined by bitcoin-rs and accepted by Core through `submitblock`.

| Outcome | Value |
| --- | --- |
| Plays | 46: 25 submissions, 12 blocks with chosen transactions, 2 waits for relative timelocks, 5 state assertions, 1 package probe, 1 reorganization |
| Submissions with the expected verdict on both nodes | 25 of 25 |
| Rejections with the expected stage on both nodes | 11 of 11 |
| Outpoints compared at the end (`gettxout`) | all funding and graph outputs; 0 differences |
| Final tips | identical on both nodes |
| Signing for all rounds, two signer processes included | 0.48 s wall |

The lifecycle:

1. **Round 0, aborted.** Four users board; the round is fully signed and
   enters both mempools. The operator double-spends its liquidity input: with
   300 sat fee both nodes refuse the replacement (`insufficient fee`); with
   the commitment's fee plus 10,000 sat both nodes accept it and drop the
   commitment. The boarding outputs remain unspent.
2. **Round 1.** The same four boarding outputs settle into a four-VTXO tree
   (commitment 584 vB, three tree transactions of 154 vB each).
3. **Round 2.** A transfers its VTXO to C, B exits cooperatively to an
   on-chain address, C refreshes, D is absent. Three forfeits bind A's, B's
   and C's round 1 VTXOs to round 2 connectors. Both nodes reject a forfeit
   before round 2 commits (`missing-inputs`) and a round 2 commitment whose
   cooperative-exit address was changed after signing (`script-verify`).
4. **Unilateral exit with the operator absent.** D publishes the root and its
   branch. Its exit is refused one block after the branch confirms
   (`non-BIP68-final`) and accepted after 12 blocks. The exit carries only D's
   signature; the tree transactions were signed in round 1.
5. **Forfeit enforcement.** D's branch exposed C's refreshed VTXO; the
   operator claims it with C's forfeit. B then publishes the A/B branch to
   double-spend its forfeited VTXO; the operator claims A and B with their
   forfeits, a replayed forfeit is refused on both nodes, and B's exit is
   refused (`missing-inputs`).
6. **Expiry, competing spends and a reorganization.** The operator's sweep of
   the round 2 batch output is refused before the 40-block expiry. After it,
   C's late tree root confirms first; a one-block reorganization on both nodes
   returns the tree root to both mempools; the operator's sweep replaces it
   (higher fee) and confirms; C's tree root is then refused.
7. **Refused boarding user.** E's boarding recovery is refused before 30
   blocks and accepted after.

Executed against: bitcoin-rs node with the native validation engine, Bitcoin
Core 31.1, and the bitcoin-rs script interpreter in-process for every signed
statement transaction.

## 2. Divergences between bitcoin-rs and Bitcoin Core

### Regtest CSV activation height

bitcoin-rs reports regtest CSV at height 432
(`Network::csv_activation_height`, `crates/primitives/src/network.rs`).
Core 31.1 reports regtest CSV active at height 1 (`getdeploymentinfo`).

The harness spends a 12-block CSV output one block after it confirms, at
height 111:

| | bitcoin-rs | Core 31.1 |
| --- | --- | --- |
| `testmempoolaccept` | allowed | `non-BIP68-final` |
| Block containing the spend | mined by bitcoin-rs and accepted as its tip | `submitblock`: `bad-txns-nonfinal` |

So below height 432 the two nodes disagree on block validity on regtest. The
harness invalidates the probe block on bitcoin-rs, confirms both tips agree,
and runs the lifecycle above height 432, where both nodes enforce CSV and
agreed on every play. Testnet4 and signet activate CSV at height 1 in both
implementations, and mainnet at 419,328, so this divergence is limited to
regtest. The first CI run (run 44789491582) ran below 432 and failed on
exactly these three premature spends.

### Arkade's tree format (TRUC, P2A, zero fee)

A version 3 transaction paying zero fee with a P2A anchor, plus a version 3
child that spends the anchor and pays for both:

| | bitcoin-rs | Core 31.1 |
| --- | --- | --- |
| Parent alone (`testmempoolaccept`) | `min relay fee not met` | `min relay fee not met` |
| `submitpackage` parent and child | rejected: parent `min relay fee not met`, child `consensus-verification-failed` | `success` |
| Child in bitcoin-rs-script, mandatory flags | accepted | |
| Child in bitcoin-rs-script, standard flags | `DiscourageUpgradableWitnessProgram` | |

The child's anchor spend is valid under consensus rules in bitcoin-rs's own
interpreter. The package fails because bitcoin-rs's standard script flags
discourage the P2A witness program, which Core exempts, and the mempool
reports that policy failure as `consensus-verification-failed`. As a result,
Arkade's zero-fee anchored trees cannot be relayed through bitcoin-rs today,
which is why this tool's trees pay their own fees.

### Other rejection wording

Both nodes reached the same verdict on every other submission. Reasons
differ in wording only; for example a replayed, already-confirmed forfeit is
`txn-already-known` on Core and `missing-inputs` on bitcoin-rs.

## 3. Adversarial cases below Bitcoin consensus

19 of 19 Rust-level cases produced the expected stage. The table in
[THREAT_MODEL.md](THREAT_MODEL.md) lists them. Highlights:

- The historical boarding failure class is a standalone regression: a
  funding output paying the user's key alone, a short value, or an
  unconfirmed output each stop the operator and the user before any
  signature (`funding-observed-script`, `-value`, `-unconfirmed`). A batch
  output paying the operator alone is rejected by the native checker
  (`batch-output-script`); the same statement, unchecked, lets the operator
  spend the batch output alone, which the bitcoin-rs interpreter accepts.
- A signer process killed after releasing a nonce cannot sign afterwards
  (`client-nonce-unavailable`); a new attempt with fresh nonces completes and
  verifies.
- Substituted partial signatures and aggregate nonces stop at the
  coordinator's partial verification; a second partial for one session stops
  at the signer.

## 4. NestedMuSig2 against flat MuSig2

Both shapes produce one 64-byte BIP340 signature per key-path input, so
on-chain size and fees are identical at every size. The difference is in
coordination. Measured by the in-process benchmark (`ark-nm2 bench`, all
signers in one process; times are signing CPU time for one round, which
signs every tree transaction):

| VTXOs | Shape | Root fan-in | Max depth | Messages | Bytes | Critical-path hops | Signing time |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | nested | 3 | 2 | 39 | 4,218 | 12 | 0.048 s |
| 4 | flat | 5 | 1 | 33 | 3,564 | 9 | 0.052 s |
| 16 | nested | 3 | 4 | 339 | 45,498 | 78 | 0.46 s |
| 16 | flat | 17 | 1 | 237 | 35,964 | 45 | 0.60 s |
| 64 | nested | 3 | 6 | 2,115 | 346,266 | 360 | 6.2 s |
| 64 | flat | 65 | 1 | 1,341 | 380,700 | 189 | 9.6 s |
| 256 | nested | 3 | 8 | 11,523 | 2,243,994 | 1,506 | 99 s |
| 256 | flat | 257 | 1 | 6,909 | 4,901,148 | 765 | 183 s |

Reading the table:

- **Coordinator design.** Nested keeps every coordinator's fan-in at three
  (two subgroups and the operator). A subgroup coordinator aggregates its own
  nonces and partials and forwards one of each. Flat puts every signer on the
  root coordinator: 257 connections at 256 VTXOs.
- **Traffic.** Nested sends more messages (one per tree edge per phase) but
  fewer bytes from 64 VTXOs up, because each context message carries only the
  sibling keys on the signer's path, not the whole cosigner list.
- **Latency.** Nested doubles the critical-path hops (three per level). With
  co-located subgroup coordinators the extra hops are local; across a wide
  network they dominate.
- **CPU.** Nested signing was 1.8 times faster at 256 VTXOs. Most of that
  comes from the reference library: `key_coefficient_for` re-hashes the whole
  key list for every coefficient, so a flat session of n keys costs O(n^2)
  hashing. A cached KeyAgg context, as libsecp256k1-zkp keeps, removes most of
  this difference. The CPU result is a property of this implementation, not
  of the schemes.
- **Policy.** The nested key commits to the grouping: moving a user between
  subgroups changes the key and the statement digest, while the flat key is
  invariant under reordering.

## 5. Native cost per VTXO

Fee rate 2 sat/vB, from signed transactions (`ark-nm2 bench`, identical for
both shapes):

| VTXOs | Commitment (boarding round) | per VTXO | Tree, all transactions | One user's unilateral exit | Mass exit, all users | per VTXO |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 584 vB, 1,168 sat | 146 vB | 3 tx, 462 vB, 924 sat | 3 tx, 445 vB, 890 sat | 1,010 vB, 2,020 sat | 253 vB |
| 16 | 1,874 vB, 3,748 sat | 117 vB | 15 tx, 2,310 vB, 4,620 sat | 5 tx, 753 vB, 1,506 sat | 4,502 vB, 9,004 sat | 281 vB |
| 64 | 7,034 vB, 14,068 sat | 110 vB | 63 tx, 9,702 vB, 19,404 sat | 7 tx, 1,061 vB, 2,122 sat | 18,470 vB, 36,940 sat | 289 vB |
| 256 | 27,676 vB, 55,352 sat | 108 vB | 255 tx, 39,270 vB, 78,540 sat | 9 tx, 1,369 vB, 2,738 sat | 74,342 vB, 148,684 sat | 290 vB |

The boarding round's commitment spends one script-path input per user; a
refresh round's commitment spends only operator liquidity (326 vB in round
2). The tree's fees are locked into the batch output when the round forms;
they are spent only if the tree is published. Native verification of every
input of the 256-VTXO round (768 inputs: commitment, tree and every exit) took
0.15 s in the bitcoin-rs interpreter.
