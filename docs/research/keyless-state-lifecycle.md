# Keyless CHECKSIG state lifecycle

The [lifecycle fixture](../../scripts/research/keyless_state_lifecycle_rpc.py)
uses the existing [F17 program](keyless-state-machine.md) to test competing
spends of one reserve. It confirms one complete path, disconnects that path
through native `invalidateblock`, and confirms a saved competing block against
the restored funding tip. Restarts check both confirmed state and a family of
unconfirmed transactions recovered from the disconnected branch.

The program and its TXCOMMIT/CAT rules retain their existing definitions.
The fixture supplies a new transaction campaign through the node's loopback
RPC interface. Both research features are enabled only on isolated regtest.
The [integration guide](keyless-checksig.md) owns build and agent instructions.

## Competing authorized paths

Both paths spend the same 100,000-sat root reserve. The root commits old state
3 and permits increment 2 or 3. Each transition checks four disclosed rows of
`s[i+1] = (s[i] + d) mod 17`. Its result selects the exact payout and successor.

| Path | Increments | First trace | First payout | Successor | Terminal trace | Terminal payout |
| --- | --- | --- | --- | --- | --- | --- |
| A | `(2, 2)` | `[3, 5, 7, 9]` | 9,000 sats to recipient 0 | State 9, 89,000 sats | `[9, 11, 13, 15]` | 87,000 sats to recipient 0 |
| B | `(3, 2)` | `[3, 6, 9, 12]` | 12,000 sats to recipient 1 | State 12, 86,000 sats | `[12, 14, 16, 1]` | 84,000 sats to recipient 1 |

Both paths pay 96,000 sats in total, with 2,000 sats in fees at each transition.
Their terminal outputs commit final states 15 and 1 respectively. The exact
successor leaves, amounts, and recipient scripts come from the same program
that the four-path campaign checks. Reserve spends use the NUMS script path
and require no script signature.

### Fixed fees and competition

Before either transaction enters the mempool, both root choices can pass
admission. Once A is resident, B competes for its input. The existing
[replacement policy](../contracts/mempool-policy.md#pol-05-replacement-cluster-and-package-policy)
requires replacement fees to cover the removed transactions and the incremental
relay charge. A root and B root each pay 2,000 sats. A's terminal child adds
another 2,000 sats to the family that a conflicting root would remove.

The application commits its input value and full output vector. A submitter
cannot increase the fee of either root while retaining the same valid policy
spend. The campaign therefore checks the expected replacement refusal and
preservation of the resident family. A block producer can select B's valid
transaction through the ordinary block-validation path. Connecting that block
must remove A and any descendant that depends on A.

Permission to spend covers both valid increments. The active chain selects
the confirmed path. Inclusion timing, competition under network load, and
fee adjustment remain separate application questions.

## Controlled rollback and replacement

Funding confirms at height 102. While that tip is current, the fixture calls
`generateblock` with B's root transaction and `submit=false`. The node returns
a solved block hash and raw block bytes. Both height and best-block hash must
remain unchanged. The fixture retains those bytes for the later submission.

The campaign then follows these checkpoints:

| Snapshot name | Height | Required observation |
| --- | ---: | --- |
| `funded` | 102 | Both root choices refer to the same confirmed reserve; the mempool is empty. |
| `candidate_b_prepared` | 102 | Preparing B's saved block preserves the complete funding snapshot. |
| `a_parent_pending` | 102 | The mempool contains A's root. |
| `a_family_pending` | 102 | A's root and terminal child are resident with their dependency intact. |
| `a_parent_confirmed` | 103 | A's root is confirmed; its terminal child remains in the mempool. |
| `a_family_confirmed` | 104 | A's terminal transaction confirms with the expected payout and state-15 commitment; the mempool is empty. |
| `a_confirmed_restarted` | 104 | The first restart preserves A's confirmed outputs and consumed inputs. |
| `rewound` | 102 | Invalidating A's height-103 block disconnects both A blocks. The funding coin returns to the chain view, and both A transactions return to the mempool. |
| `rewound_restarted` | 102 | The second restart preserves the restored reserve and the exact resident A family. |
| `b_parent_confirmed` | 103 | The saved B block connects its root and removes the conflicting A family from the mempool. |
| `b_child_pending` | 103 | B's terminal child enters the mempool against its state-12 successor. |
| `b_family_confirmed` | 104 | B's terminal child confirms with the expected payout and state-1 commitment; the mempool is empty. |
| `b_confirmed_restarted` | 104 | The third restart preserves B's confirmed state and A's absence from the active chain. |

The final shutdown gives four daemon exits in total. A completed campaign
requires each exit code to be zero. Each restart uses the same data directory
for that campaign, with the expected tip checked before further submissions.

### Chain and mempool UTXO views

Every relevant outpoint is inspected through both forms of `gettxout`:

| RPC argument | View |
| --- | --- |
| `gettxout(txid, vout, false)` | The current committed chain UTXO set. |
| `gettxout(txid, vout, true)` | The chain UTXO set with the mempool's spends and outputs applied. |

After rollback, the funding coin is present in the chain-only view. The
readmitted A root spends it in the mempool view. A's successor is unconfirmed
and its child consumes it. The terminal A payout can be visible through the
mempool before either A transaction is confirmed again. These observations
must be recorded separately so a hidden coin in one view cannot be mistaken
for a failed rollback.

The restored mempool family must retain its transaction and witness
identities. Its receipt records `depends`, `spentby`, ancestor and descendant
counts and sizes, virtual size, and all reported fee values. The child's
dependency must name A's root. The restart comparison preserves those rows
and both coin views. `mempool_sequence` belongs to one daemon process and can
reset when the process restarts, so the cross-restart comparison excludes
that counter.

The fixture also checks fork coinbases in both views. All A and saved B
coinbases are absent at the rewound funding tip, before and after restart.
At the completed B tip, B's coinbases are present and A's remain absent.
The coinbase checks repeat after the final restart.

The block builder can leave transaction fees unclaimed. The initial run's
five explicit blocks each paid the 5,000,000,000-sat subsidy to the first
coinbase output. Transition fees are checked from the spent amount and
confirmed output vector; the receipt retains the actual coinbase amount.

### Fresh proof from the displaced state

After B's root confirms, its successor commits old state 12. The fixture
submits trace `[9, 12, 15, 1]` with increment 3 against that successor. Each
arithmetic step is valid and the final result is 1, which selects B's authorized
terminal output vector. The trace's first row violates the executing leaf's
old-state commitment.

The witness is rebuilt for B's current outpoint, spent key, and tapleaf. Its
native rejection checks the state mismatch with current transaction context.
The honest B trace `[12, 14, 16, 1]`, using increment 2, must remain eligible
and subsequently confirm.

### Rejection boundaries

The campaign keeps policy conflicts, missing inputs, and Script failures as
separate observations. Each refusal must preserve the current tip and the
resident mempool family.

| Case | Expected result | Purpose |
| --- | --- | --- |
| `child_without_parent` | Dry-run `missing-inputs` | A's child needs its actual parent output. |
| `equal_fee_parent` | Dry-run `insufficient fee`; broadcast code -26 | B's fixed-fee root cannot replace A's resident root. |
| `conflict_with_child` | Dry-run `insufficient fee`; broadcast code -26 | The resident A child remains part of the family that a conflict would remove. |
| `replayed_old_state` | Dry-run `script-verify-flag-failed`; broadcast code -26; direct block code -25 with `NUMEQUALVERIFY` | A valid trace from old state 9 cannot authorize B's state-12 successor. |
| `stale_a_child` | Dry-run `missing-inputs`; broadcast and direct block code -25 | The displaced A child cannot spend its absent parent after B completes. |

The saved B block also receives a submission while A is still the active
branch. Its expected BIP22 result is `inconclusive-not-best-prevblk`. After
the explicit rollback, the same saved bytes must return `null` and advance
the tip. Successful `invalidateblock` also returns `null`.

## Native ownership and proof scope

Chainstate owns rollback planning, exact disconnects, and the durable head.
The node composes those transitions with mempool reconsideration and committed
effects. The fixture observes these existing owners through RPC.

| Existing contract | Observation exercised by the campaign |
| --- | --- |
| [RCV-08](../contracts/recovery.md#rcv-08-exact-disconnect-and-reorg) | Disconnect restores the funding state; a clean restart can resume at the committed ancestor. |
| [MPL-04](../contracts/mempool-mutations.md) | Reconsideration admits the disconnected parent before its child while the chain-change fence is held. |
| [POL-05](../contracts/mempool-policy.md#pol-05-replacement-cluster-and-package-policy) | A fixed-fee conflict leaves the resident family intact under replacement policy. |
| [EVT-02](../contracts/chain-events.md#evt-02-ordered-commit-and-best-effort-observer-delivery) | The committed B block removes conflicting mempool transactions and descendants before the generation becomes stable. |
| [SYNC-04 and SYNC-05](../contracts/synchronization.md) | RPC outcomes distinguish refusal from committed progress, and the observed tip and coin state agree. |

These contracts remain authoritative. The campaign adds application-specific
evidence at their existing call boundaries. The staging semantics profile also
selects the smallest existing owner proofs for the relevant composition:

```sh
cargo test --locked --jobs 2 \
  -p bitcoin-rs-node --no-default-features \
  --features fjall,experimental-keyless-checksig-regtest,experimental-op-cat-regtest \
  --test suite \
  invalidateblock_readmits_parent_before_child_in_dependency_order

cargo test --locked --jobs 2 \
  -p bitcoin-rs-mempool \
  --features experimental-keyless-checksig-regtest,experimental-op-cat-regtest \
  --lib remove_for_block_distinguishes_mined_from_conflicts
```

The first proof covers parent-before-child readmission through the node's
reorg composition. The second checks removal of a mined conflict and its
descendant through the mempool gateway.

The RPC registry currently implements `invalidateblock` and leaves
`reconsiderblock` unimplemented. `submitblock` connects a child of the applied
tip. The saved B block is therefore submitted after the explicit rollback to
its parent. This campaign establishes controlled rollback and replacement.
Peer discovery and selection of a heavier branch retain their existing P2P
process tests. Crash recovery and storage-fault guarantees remain with
`RCV-04` and its process and fault-injection lanes.

Checkpoint restoration excludes invalid subtrees from the header tree. A
restarted node can therefore omit the old invalidated headers. The fixture's
persistence claims concern the restored tip, coin state, and mempool family.
Raw block bytes needed for later evidence are retained before invalidation.

## Run locally and retain evidence

Use the prerequisites and source controls in the
[integration guide](keyless-checksig.md#run-locally). From a clean checkout:

```sh
python3 scripts/research/keyless_checksig_stage.py \
  --profile regtest --output target/keyless-staging/lifecycle-01 \
  --jobs 2 --timeout 900 --build-timeout 1800
```

The `regtest` and `full` profiles include `state-lifecycle-regtest` alongside
the existing funded payout and four-path state-machine fixtures. Its receipt
is `state-lifecycle-regtest/report.json` below the staging output directory.
Use `--profile full` to include offline tests and the native semantics matrix.
Each attempt requires a fresh output directory.

For a direct invocation against an existing executable:

```sh
python3 scripts/research/keyless_state_lifecycle_rpc.py \
  target/quickstart/bitcoin-rs \
  --output target/keyless-lifecycle/direct-01
```

The fixture retains its report and node log. The enclosing staging report
owns source provenance and checks the executable identity. A prebuilt binary
requires the runner's `--binary`, `--binary-sha256`, and `--binary-source`
arguments. Retain the original build receipt that supports that declaration.

### Receipt fields

The lifecycle receipt uses `schema_version: 1` and
`fixture: "keyless-state-lifecycle"`. Its named records connect each claimed
result to the transaction and chain state that produced it.

| Field | Retained evidence |
| --- | --- |
| `funding` | Raw transaction, txid and wtxid, input, outputs, witness, fee, admission result, block hash, and height. |
| `transactions` | `a_parent`, `a_child`, `b_parent`, and `b_child`, with their paths, traces, program and state, raw transactions, witness data, exact outputs, and observed confirmations. |
| `blocks` | `funding` and all four transition blocks, with raw bytes, hash, parent, height, transaction identities, and the coinbase payout. |
| `candidate_b` | The saved B block, retained before A is admitted. It must equal the later `blocks.b_parent` record. |
| `snapshots` | The 13 named checkpoints above, in campaign order. |
| `admissions` | Honest dry runs and their unchanged before/after snapshots. A's transactions and B's child also retain submitted txids; B's root enters through its saved block. |
| `rejected` | The five named cases above, with transaction and witness identities, traces, expected boundaries, returned errors, and unchanged before/after snapshots. |
| `operations` | `stale_b_submit`, `invalidate`, and `submit_b`, including their arguments, returned results, and surrounding snapshots. |
| `restart_checks` | The before/after snapshot names, expected height and tip, and comparison result for each restart. |
| `coinbase_checks` | Both views of fork coinbases at `rewound`, `rewound_restarted`, `b_family_confirmed`, and `b_confirmed_restarted`. |
| `node_exit_codes` | All four daemon exit codes, including the final shutdown. |

Each snapshot retains `height`, `bestblock`, `height_hash`, `peer_count`,
`is_apply_halted`, and `is_closed_for_recovery`. Its `mempool` record holds
`txids` and `mempool_sequence`; `entries` holds the dependency rows keyed by
txid. Each named coin has a `chain` view and an `overlay` view. A present coin
records its amount in sats, scriptPubKey, confirmations, coinbase flag, and
best-block hash. Absent coins are `null`.

The receipt names the executable through `binary_sha256` and records start
and finish times. Its successful summary requires `active_family: "b"`,
`final_state: 1`, `final_height: 104`, `confirmed_transitions: 4`,
`rewind_depth: 2`, `rejection_count: 5`, and zero peers or script signatures.
The four confirmations count both historical A transactions and the final
active B pair. The surrounding records supply the evidence for
`restart_preserved_state` and `clean_shutdowns`.

The [staging validator](../../scripts/research/keyless_state_lifecycle_receipt.py)
reconstructs the funding transaction and all four transitions from the finite
program specification. It verifies block hashes, regtest proof of work,
transaction Merkle roots, witness commitments, coinbase height commitments,
canonical length encodings, and the exact transaction in each block. The
saved B block must match the later accepted bytes. Explicit phase ledgers
check every named coin in both
RPC views, together with resident transaction identities, dependency sizes,
fees, and the expected within-process mempool sequence changes.

The [receipt tests](../../scripts/tests/test_keyless_state_lifecycle_stage.py)
build independent transactions and solved blocks from specified arithmetic
and amounts. They reject missing evidence, copied failures, wrong ancestry,
ghost outputs, lost restored coins, and changed dependency records. A positive
control permits different sequence baselines after restart while retaining
each process's required mutation counts.

### Evidence status

The first complete native run passed on 2026-11-13. It recorded four
confirmed transitions across the two paths, five refusals, 13 snapshots,
and three successful restarts. All four daemon exits were zero. B finished
at height 104 with state 1.

The direct receipt was retained at
`target/keyless-lifecycle/attempt-03/report.json`, with SHA-256
`7a94c177bed3851860645d9957fc95fcfeb24802a56a3fdbe293624b48f71391`.
Its executable hash was
`fe506c638478d173edd267422856b9fb02c8ab424b694b6c81554dce2a48caa6`,
from the [verified state-machine build](keyless-state-machine.md#verified-native-evidence).
The direct run used Python sources from the working tree. The staging runner
records a source revision and validates this receipt alongside the other
funded campaigns. Its hosted workflow retains the source archive and tested
executable with the stage logs.

## Further application work

This campaign retains the finite F17 statement and its precompiled successors.
General proof-system integration still needs an authenticated application
statement and transcript encoding. Arbitrary successor programs need their
own commitment construction. Fee adjustment and inclusion under sustained
competition require further transaction campaigns. The lifecycle results
must keep those scope boundaries when cited by a local agent.
