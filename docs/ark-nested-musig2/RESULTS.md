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
  (conformance, ark-core interop, regtest lifecycle, 16- and 64-VTXO mass
  exits, benchmark). Runs 44794108747 (`ac99bde`) and 44796328008
  (`86e9d60`) passed; run 44789491582 (`95f3ddc`) failed on the three
  premature CSV spends described in section 2, before the harness moved the
  lifecycle above height 432.

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
| Signing for all rounds, adversarial cases and two signer processes included | 0.31 s wall |
| Source and binaries | `fa87365`, clean tree; bitcoind SHA-256 `986e63b3…` as pinned in `crates/rpc/core-compat.toml` |

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
| 4 | nested | 3 | 2 | 39 | 4,218 | 12 | 0.04 s |
| 4 | flat | 5 | 1 | 33 | 3,564 | 9 | 0.04 s |
| 16 | nested | 3 | 4 | 339 | 45,498 | 78 | 0.46 s |
| 16 | flat | 17 | 1 | 237 | 35,964 | 45 | 0.66 s |
| 64 | nested | 3 | 6 | 2,115 | 346,266 | 360 | 6.2 s |
| 64 | flat | 65 | 1 | 1,341 | 380,700 | 189 | 8.9 s |
| 256 | nested | 3 | 8 | 11,523 | 2,243,994 | 1,506 | 94 s |
| 256 | flat | 257 | 1 | 6,909 | 4,901,148 | 765 | 170 s |

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

## 6. Mass unilateral exit at scale on both nodes

`--scale N` builds one N-user round from real regtest funding and then exits
every user without the operator: the commitment, each tree level in its own
block, and every user's CSV exit after 12 blocks.

| VTXOs | Plays | L1 transactions | Unexpected verdicts | UTXO differences | Wall time |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 55 | 1 + 15 + 16 | 0 | 0 | 21 s |
| 64 | 201 | 1 + 63 + 64 | 0 | 0 | 31 s |
| 256 | 779 | 1 + 255 + 256 | 0 | 0 | 137 s |

Executed against: bitcoin-rs node with the native engine and Bitcoin Core
31.1. Hosted CI run 44796328008 reproduced the 16- and 64-VTXO runs (55 and
201 plays, 0 unexpected verdicts, 0 UTXO differences).

## 7. Nova mode

The proving lane is `integrations/ark-transition-nova` on
`patrickdugan/zk-rusto-no-bitcoino`, branch `feat/ark-transition-nova`,
nova-snark 0.76 over Pallas/Vesta with IPA, Spartan compression. Verifier key
digest `22ad3282b71196a227d95b2216921a78e8d362d96702a3377347c0d085dfcdad`.
Timings are on 8 threads in WSL while other jobs shared the machine.

| Witness | Steps | Prove (fold + compress) | Verify, full / succinct | Proof | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ark round, 4 VTXOs (exported by `ark-nm2`) | 28 | 14.3 s | 0.21 s / 0.23 s | 11,104 B | 182 MB |
| Ark round, 16 VTXOs (exported by `ark-nm2`) | 112 | 35.8 s | 0.17 s / 0.17 s | 11,104 B | 182 MB |
| Ark round, 64 VTXOs (exported by `ark-nm2`) | 448 | 108.6 s | 0.21 s / 0.18 s | 11,104 B | 189 MB |
| Synthetic Ark-shaped graph, 256 VTXOs | 1,792 | 480.4 s | 0.26 s / 0.18 s | 11,104 B | 181 MB |

The circuit has 1,050 constraints per step; setup takes 3.7 s. Folding costs
about 0.26 s per step, so proving is linear in the graph, about seven steps
per VTXO. Verification and proof size are constant.

The prover's mutation run on the four-VTXO witness rejected 22 of 22
mutations: changed output values, a duplicated spend identifier and a fee
above the bound are refused both by the native precheck and, with the
precheck bypassed, by the circuit (an unsatisfied step). The verifier refuses
a proof checked against another statement digest or a public file rewritten
for it; proofs truncated by half or by one byte, with a byte appended or one
byte flipped; three altered final-state fields; proofs swapped between two
witnesses in both directions; an altered step count, verifier-key digest,
schema, expectation block or Fiat-Shamir challenge.

### The same round statements, native and Nova

`run-ark-nova-mode.py` took the round 1 and round 2 statements that the clean
lifecycle run signed and settled on both nodes, and checked each natively and
with a Nova proof:

| Statement | Native check (rules and every signed input) | Nova prove | Nova verify through `ark-nm2 verify-proof` | Proof |
| --- | ---: | ---: | ---: | ---: |
| Round 1 (4 VTXOs, 28 steps) | accepted, 0.012 s | 15.3 s, 151 MB peak | accepted, 3.77 s | 11,104 B |
| Round 2 (2 VTXOs, 3 forfeits, 32 steps) | accepted, 0.010 s | 15.4 s, 151 MB peak | accepted, 3.50 s | 11,104 B |

The end-to-end verify time includes 3.66 s in which `ark-nova verify`
rebuilds the public parameters to recompute the verifier-key digest; with
the key cached, verification takes 0.15 to 0.26 s (table above).

Envelope controls on the round 1 proof, all with the expected stage:

| Control | Rejected at |
| --- | --- |
| Expected network testnet4 for a regtest statement | `network` |
| Round 1 proof attached to the round 2 statement | `statement-digest` |
| Fee bound in the public file raised by 1 sat | `public-inputs` |
| Verifier-key digest not the pinned one | `verifier-key` |
| Public file with an unknown schema | `unrecognized-schema` |
| Witness with its last item removed | `incomplete-transcript` |
| Proof truncated to half its length | `nova-verifier` |
| Valid proof, round 1 tree signature altered | proof accepted; native check rejects at `script-verification` |

The last control is the rule that a proof never makes an invalid Bitcoin
spend acceptable: the settlement verdict needs the native and consensus
checks, and the proof does not replace them.

## 8. Is the proof worth its cost?

The proof establishes per-transaction value conservation, the fee bound and
single-use spend identifiers over the records it commits to. Section 7 and
[NOVA_STATEMENT.md](NOVA_STATEMENT.md) list what it does not establish:
signatures, script execution, inclusion, chain and UTXO state, and the link
from records to Bitcoin transactions.

Against that coverage, measured on the same statements:

| Question | Native | Nova | Verdict |
| --- | --- | --- | --- |
| Does it make settlement safer? | Bitcoin consensus validates every spend; the native checker re-derives every rule | Covers a subset of the native rules, none of the consensus rules | No. A user's exit, a forfeit and a sweep stand or fall on Bitcoin consensus alone |
| Verifier CPU for the covered relation | Microseconds of integer arithmetic over the statement | 0.15 to 0.26 s | Native is cheaper at every size measured |
| Verifier CPU for everything the native checker does (rules and all scripts) | 0.15 s for 768 inputs at 256 VTXOs, linear | 0.2 s, constant, but covers no scripts | Not substitutable: the proof cannot replace script checks |
| Bytes a third-party auditor downloads | The statement: 1,671 B at 4 VTXOs, 89,621 B at 256 (about 350 B per VTXO) | 11,104 B proof plus a small public file | The proof is smaller from about 32 VTXOs up, for an auditor who accepts the operator's record commitment `r1` |
| Prover cost | none | about 0.26 s per step on 8 threads, 1,792 steps (480 s) at 256 VTXOs | Off the signing path it is affordable; on it, proving is five times the 94 s nested signing time at 256 VTXOs |
| Under operator failure or a mass exit | Exits are L1 transactions: 290 vB per VTXO at 256 VTXOs | Adds nothing; no exit, forfeit or sweep consumes a proof | No benefit |

Minimum batch size at which proving pays, under each assumption:

1. The verifier has the statement and Bitcoin settles every spend: never.
2. A bandwidth-limited auditor who trusts the operator's commitment to the
   records and wants conservation and uniqueness for many rounds: from about
   32 VTXOs per round, where the statement outgrows the 11.1 KB proof.
3. A verifier that cannot run Bitcoin script (a BitVM-style chain or a
   light client): the proof would have to add Taproot script execution
   (section 9) and a link from records to transactions before it can stand
   in for anything that verifier needs.

Hierarchical signing, by contrast, changes coordination without changing L1
cost: it bounds every coordinator's fan-in at three and cut signing bytes in
half at 256 VTXOs, at the price of more messages and twice the critical-path
hops.

## 9. Unresolved obligations

- **Taproot in M17.** Every Ark spend is Taproot; M17 proves legacy, P2SH and
  witness v0 only. A Taproot extension (tapscript signature version, BIP341
  sighash claims, control-block checks, validation weight budget, and Core's
  2,239 Taproot vectors) was not built, so no Ark spend is proven at script
  level.
- **Records to transactions.** The Nova relation commits to records derived
  natively from the statement bytes; no SHA-256 or txid relation is in the
  circuit.
- **SP1 and BitVM3.** Not attempted. The precondition (native Nova verifier
  accepts, mutations fail) holds, but the M14 verifier consumes SP1 Groth16
  proofs, not this circuit's proofs, so a wrapper is a separate build.
- **NestedMuSig2.** Security of nesting beyond depth two, and the X-only
  intermediate binding, rest on the draft; see THREAT_MODEL.md.
- **Testnet4.** The runner's preflight passed against a pruned Core 31.1
  testnet4 node at height 162,447. Funding, the round stage and any broadcast
  wait for a funded faucet outpoint.
- **Live Arkade or Bark.** No test ran against an arkd or captaind server.
  Interoperability is the byte-identical default VTXO script.
