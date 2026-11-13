# Keyless CHECKSIG bounded state machine

The [compiler](../../scripts/research/keyless_state_machine.py) builds a
two-stage program over the field F17. Each spend supplies its complete
four-row arithmetic trace. Native Script checks every row and uses the result
to select the payout and successor output. The
[live fixture](../../scripts/research/keyless_state_machine_rpc.py) funds all
four paths, confirms eight transitions, and checks rejection and restart
behavior on isolated regtest.

The [state lifecycle campaign](keyless-state-lifecycle.md) follows competing
paths from the same reserve through controlled rollback, mempool recovery,
and replacement. It reuses this program's statement and finite successors.

This milestone uses the TXCOMMIT and CAT rules described in the
[integration guide](keyless-checksig.md). Both experimental node features must
be enabled. The proof in this program consists of disclosed field values.
General proof-system integration and arbitrary dynamic successor programs
remain separate engineering work.

## Checked program

The root starts at state 3. A witness chooses an increment `d` of 2 or 3 and
supplies four rows:

```text
s0 = old_state
s1 = (s0 + d) mod 17
s2 = (s1 + d) mod 17
s3 = (s2 + d) mod 17
result = s3
```

Script verifies the committed old state, the allowed increment, all three
recurrences, and the range `0 <= si < 17`. Each field value must use its
canonical Script number encoding. Zero is the empty byte string; values 1
through 16 use one byte. The compiler reduces each sum by 17 when needed.
The bounds make one subtraction sufficient.

The program identity is:

```text
SHA256("BIPSpace/Keyless-CHECKSIG/F17/full-trace/v1")
= 22f210abc736543ed343dfeede683926bae44ddb62c673633381615a86400648
```

Each leaf embeds this identity and checks the witness copy for equality.
Its Script also commits the old state and the amount of the coin that it
spends. The terminal state commitment uses the tagged hash:

```text
tag = "BIPSpace/Keyless-CHECKSIG/F17/state/v1"
message = program_id[32] || depth_u32_le[4] || state_u8[1]
commitment = SHA256(SHA256(tag) || SHA256(tag) || message)
```

The root has depth 1 and each successor has depth 0. Terminal commitments
encode depth 0. The state byte in this message is unsigned, so state zero
would use `00` even though its witness Script number is empty.

## Funds and finite successors

Each root reserve holds 100,000 sats. The result chooses recipient 0 or 1,
using the public test keys in the
[base fixture](../../scripts/research/keyless_checksig_rpc.py). Results 9, 15,
and 4 select recipient 0; results 12 and 1 select recipient 1.

The first transition pays `result * 1,000` sats. Its second output retains
the remaining funds in the selected successor, after a 2,000-sat fee. A
terminal transition pays the successor's value less another 2,000-sat fee.
Its second output has zero value and Script `OP_RETURN <commitment32>`.
The order of both outputs is fixed.

| Increments | First trace | First payout | Successor value | Terminal trace | Terminal payout |
| --- | --- | --- | ---: | --- | --- |
| `(2, 2)` | `[3, 5, 7, 9]` | 9,000 sats to recipient 0 | 89,000 sats | `[9, 11, 13, 15]` | 87,000 sats to recipient 0 |
| `(2, 3)` | `[3, 5, 7, 9]` | 9,000 sats to recipient 0 | 89,000 sats | `[9, 12, 15, 1]` | 87,000 sats to recipient 1 |
| `(3, 2)` | `[3, 6, 9, 12]` | 12,000 sats to recipient 1 | 86,000 sats | `[12, 14, 16, 1]` | 84,000 sats to recipient 1 |
| `(3, 3)` | `[3, 6, 9, 12]` | 12,000 sats to recipient 1 | 86,000 sats | `[12, 15, 1, 4]` | 84,000 sats to recipient 0 |

Each path pays 96,000 sats in total and consumes 4,000 sats in fees. The final
row determines the state in the terminal commitment.

The compiler builds the two terminal leaves first. It derives their P2TR
outputs, then embeds those exact output scripts and amounts in the root's
branches. Every leaf uses the BIP341 NUMS internal point. The current root
Script is 701 bytes; each terminal Script is 877 bytes. All three leaves and
their permitted branches exist before funding. The witness selects among
those finite branches after funding.

Reserve and successor spends require no script signature. Ordinary P2TR
still has a key path, whose signing secret is assumed unknown under the
NUMS construction. P2MR requires its own native implementation. Support for
an arbitrary new successor program would also require a new construction
and evidence for that construction.

## Transaction context constructed by Script

Each policy constructs its epoch-prefixed TapSighash message in Script.
The following restrictions are part of the checked application statement:

| Field | Rule |
| --- | --- |
| Transaction version | 2 |
| Locktime | 0 |
| Input vector | One input, checked at input index 0 |
| Spent amount | The leaf's committed reserve amount |
| Sequence | `0xfffffffd` |
| Spent output Script | P2TR with a 32-byte output key |
| Outputs | The exact ordered pair selected by the checked result |
| Hash type and extension | `SIGHASH_DEFAULT`, script path, key version 2 |
| Annex | Absent |
| Code separator | Absent, with position `0xffffffff` |

The witness supplies a 36-byte outpoint, a 32-byte spent output key, and a
32-byte tapleaf hash. Script checks the widths and hashes these fields into
the transaction message. The outpoint uses Bitcoin's transaction wire order
and a little-endian output index. The spent Script is serialized as
`22 51 20 || output_key`, including its CompactSize length. Script supplies
the fixed fields and the known input amount itself.

After it verifies the trace, Script serializes the authorized outputs and
computes `sha_outputs`. It assembles the 212-byte message and applies the
`TapSighash` tagged hash. TXCOMMIT compares that candidate with the native
interpreter's digest of the actual transaction, UTXO, and executing tapleaf.
This equality binds the candidate context fields to the spend. The existing
P2TR control-block check authenticates the executing program.

The fixed single-input context is tested with an additional funded input.
Fresh witnesses also accompany the version, locktime, sequence, and output
mutations. These cases exercise the application's restrictions
with current context data. The native TXCOMMIT primitive retains its wider
BIP341 context support, including annex hashing.

## Honest controls and wrong starting states

Before a root is spent, both increments pass `testmempoolaccept` against the
same outpoint. Both terminal choices receive the same check against one
confirmed successor. A repaired honest root trace passes again after the
root rejection campaign. These five positive controls accompany the eight
confirmed spends.

Two attacks use correct arithmetic and an authorized final result:

| Leaf's committed old state | Submitted trace | Increment | Authorized final result |
| ---: | --- | ---: | ---: |
| 3 | `[0, 3, 6, 9]` | 3 | 9 |
| 9 | `[6, 9, 12, 15]` | 3 | 15 |

Each witness includes the actual transaction's current context. Native
validation rejects the mismatch between the first row and the leaf's old
state. The earlier root trace is also replayed against a successor with
fresh context. These checks establish the starting-state requirement in
addition to the recurrence and output checks.

Each recurrence edge also has a separate negative case. Those traces retain
old state 3, canonical field values, increment 2, and authorized final result
12. The transaction uses the result-12 output vector. Exactly one edge fails
in each case, so a check at another edge cannot conceal a missing guard.

## Rejection matrix

Every case is submitted to `testmempoolaccept`, `sendrawtransaction`, and
`generateblock`. The receipt records all three outcomes and verifies that
the chain height and best block hash remain unchanged. Root attacks run at
height 102, successor attacks at height 103, and spent-input replay at
height 104.

| Case | Stage | Mutation |
| --- | --- | --- |
| `wrong_old_state_valid_trace` | Root | Valid trace starts at 0 and ends at authorized result 9. |
| `substituted_program` | Root | Change the witness program identity while retaining the actual leaf and control block. |
| `trace_out_of_range_high` | Root | Set a row to 17. |
| `trace_out_of_range_negative` | Root | Encode a row as -1. |
| `broken_first_edge` | Root | Use `[3, 8, 10, 12]` with increment 2 and result-12 outputs. |
| `broken_middle_edge` | Root | Use `[3, 5, 10, 12]` with increment 2 and result-12 outputs. |
| `broken_last_edge` | Root | Use `[3, 5, 7, 12]` with increment 2 and result-12 outputs. |
| `noncanonical_trace_number` | Root | Encode 5 as two bytes, `05 00`. |
| `unauthorized_delta` | Root | Supply increment 19 with the increment-2 trace. |
| `result_output_mismatch` | Root | Pair result 9 with result 12's output vector. |
| `wrong_payout_recipient` | Root | Replace the selected recipient. |
| `wrong_payout_amount` | Root | Increase the payout by one sat. |
| `wrong_successor_state` | Root | Select the successor for old state 12 after result 9. |
| `wrong_successor_program` | Root | Select a successor compiled under another program identity. |
| `wrong_successor_amount` | Root | Decrease the successor value by one sat. |
| `extra_output` | Root | Append a zero-value output. |
| `reordered_outputs` | Root | Reverse the authorized output pair. |
| `additional_funded_input` | Root | Add an unspent 100,000-sat input with a valid witness. |
| `fresh_version_change` | Root | Change version to 1 and rebuild the witness. |
| `fresh_locktime_change` | Root | Change locktime to 1 and rebuild the witness. |
| `fresh_sequence_change` | Root | Change sequence to `0xfffffffe` and rebuild the witness. |
| `short_outpoint_context` | Root | Supply 35 outpoint bytes. |
| `long_outpoint_context` | Root | Supply 37 outpoint bytes. |
| `short_spent_key_context` | Root | Supply 31 output-key bytes. |
| `long_spent_key_context` | Root | Supply 33 output-key bytes. |
| `short_tapleaf_context` | Root | Supply 31 tapleaf bytes. |
| `long_tapleaf_context` | Root | Supply 33 tapleaf bytes. |
| `wrong_outpoint_context` | Root | Change an outpoint byte at the correct width. |
| `wrong_spent_key_context` | Root | Change an output-key byte at the correct width. |
| `wrong_tapleaf_context` | Root | Change a tapleaf byte at the correct width. |
| `annex` | Root | Add an annex to the fixed no-annex policy. |
| `changed_control` | Root | Flip the control block's output parity. |
| `proof_replay_successor` | Successor | Reuse the root's trace with fresh successor context. |
| `wrong_old_state_successor_valid_trace` | Successor | Valid trace starts at 6 and ends at authorized result 15. |
| `terminal_state_commitment_change` | Successor | Change the final commitment bytes. |
| `terminal_recipient_change` | Successor | Replace the selected recipient. |
| `terminal_payout_amount_change` | Successor | Decrease the payout by one sat. |
| `terminal_output_reordered` | Successor | Reverse payout and state-commitment outputs. |
| `spent_input_replay` | Consumed root | Submit the previously eligible, unbroadcast alternative after the root has been spent. |

The 39 cases have these expected error boundaries:

| Cases | Mempool reason | Admission RPC code | Direct block result |
| --- | --- | ---: | --- |
| 37 cases at Script validation | `script-verify-flag-failed` | -26 | Code -25 with `block-script-verify-flag-failed` |
| `annex` | `bad-witness-nonstandard` | -26 | Code -25 with `block-script-verify-flag-failed` |
| `spent_input_replay` | `missing-inputs` | -25 | Code -25 with `bad-txns-inputs-missingorspent` |

The annex therefore receives a direct consensus check after relay policy
rejects it. Spent-input replay uses the alternate transaction that was never
confirmed, so its error identifies the consumed input.

## Confirmation and receipt requirements

The fixture creates fresh node data with full native validation and Fjall
storage. It binds RPC to loopback, disables DNS seeds, removes inherited
`BITCOIN_RS_*` settings, and checks zero connected peers. Loopback RPC ignores
proxy settings. All coins come from regtest mining.

After 101 maturity blocks, one funding transaction creates four root reserves
and a separate coin for the additional-input attack. Funding confirms at
height 102. Four first transitions confirm at height 103. The fixture stops
and restarts the daemon, then verifies the payouts and every required
successor. Four terminal transitions confirm at height 104, followed by
another restart and inspection of the committed output vectors. It checks
that spent inputs remain consumed and the spare attack coin remains unspent.
The final shutdown must complete with exit code zero. A passing receipt
contains exactly `[0, 0, 0]` for the three daemon exits.

Each invocation requires a new output directory. It writes `report.json`,
including a failed report if execution raises an error, and retains
`node.log` when a node was started. The fixture refuses to reuse an existing
output directory. Its report includes:

- Binary SHA256, program identity, field parameters, network, and path list.
- Funding transaction, admission, output vector, and confirmation block.
- Eight raw transition transactions with witness data and executing scripts;
  old and new states; input outpoints; expected and observed output values;
  the observed input value and 2,000-sat fee; and confirmation heights.
- Five positive admission controls and all 39 rejected transactions with
  their contexts, RPC errors, and unchanged chain tips.
- Both restart observations, peer count, daemon exit codes, and final status.

For a completed run, inspect these fields:

| Receipt field | Required value |
| --- | --- |
| `status` | `passed` |
| `confirmed_transitions` | 8 |
| `rejection_count` | 39, with the complete named manifest |
| `final_height` | 104 |
| `both_root_alternatives_eligible`, `both_child_alternatives_eligible` | `true` |
| `restart_checks` | Heights 103 and 104, each with `preserved: true` |
| `node_exit_codes` | `[0, 0, 0]` |
| `peer_count`, `script_signatures` | 0 |

The staging runner owns source provenance. Its enclosing receipt records
the source revision or dirty-source fingerprints, commands, log hashes, and
the binary's origin. A supplied binary's declared source and its measured
SHA256 are separate facts. Preserve its original build receipt with the run.

Receipt validation reconstructs the funding transaction, all eight transitions,
the five positive controls, and every named attack. It checks their raw bytes
and witness identities against the expected contexts. The state and payout
checks derive the arithmetic and amounts from the program specification.
Copying an unrelated rejection into another attack's entry fails validation.
Both transaction links and the observed output values must agree across stages.

### Verified native evidence

[Keyless CI run 43356286189](https://github.com/patrickdugan/bitcoin-rs/actions/runs/43356286189)
confirmed all eight transitions, checked all 39 rejections, and preserved both
restarts with zero peers and exits `[0, 0, 0]`. The state-machine receipt passed
the staging runner's strict validation. The program-identity substitution
reached `EQUALVERIFY`, and each isolated recurrence-edge attack reached
`NUMEQUALVERIFY`.

The hosted executable has SHA256
`fe506c638478d173edd267422856b9fb02c8ab424b694b6c81554dce2a48caa6`.
The archived CI source is merge
`2e8f5f1f588ccf3bc85e8c2a8399bd1a05368a98`, with tree
`c9f0f775b4ff5b08376505bb010b63ca731ba726`. The same tree belongs to published
revision `188e2d78fbb623a12a42772120a2aa4e437905c1`. Independent verification
matched all 1,325 tracked source files and executable modes. The state-machine
receipt's SHA256 is
`2d9b138d78d0bbfab59670aec60d475a88476fc6e518f9946336676f0b2a237c`.
The run's artifacts retain the executable, source archive, enclosing staging
report, and fixture receipts.

## Run locally

Use the Linux or WSL2 prerequisites in the
[integration guide](keyless-checksig.md#run-locally).
The compiler's independent subset interpreter and transaction-hash oracle run
without a node:

```sh
python3 -m unittest discover -s scripts/tests \
  -p 'test_keyless_state_machine.py' -v
```

From a clean checkout, build and run the live fixtures through staging:

```sh
python3 scripts/research/keyless_checksig_stage.py \
  --profile regtest --output target/keyless-staging/state-machine-01 \
  --jobs 2 --timeout 900 --build-timeout 1800
```

The `regtest` and `full` profiles run `keyless-regtest`,
`state-machine-regtest`, and `state-lifecycle-regtest`. The state-machine receipt is under
`state-machine-regtest/report.json` in the staging output directory. Use
`--profile full` to include the offline suites and native semantics matrix.
For ongoing work, `--allow-dirty` records the source fingerprints. Every
retry needs a fresh output path.

For a direct run against an existing executable:

```sh
python3 scripts/research/keyless_state_machine_rpc.py \
  target/quickstart/bitcoin-rs \
  --output target/keyless-state-machine/direct-01
```

That direct command records the executable hash in the fixture receipt.
Use the staging runner with `--binary`, `--binary-sha256`, and
`--binary-source` when the run also needs checked binary identity and source
provenance in its enclosing receipt.

## Remaining application work

This program authenticates a finite computation against its committed old
state and exact successor leaves. Extending it requires a defined statement
for each new verifier and an authenticated link from that statement to the
transaction outputs. Nova and Circle-STARK integration retains its own proof
and provenance requirements. A compressed proof would need evidence for its
verifier and transcript encoding; the current program discloses every row.

Arbitrary dynamic states need a construction for their successor program
commitments, including initialization and canonical encoding. Longer
verification chains need proof-fragment availability and a recovery rule
for stalled execution. The lifecycle campaign exercises controlled rollback
and a competing path through the current finite program. Fee changes,
inclusion under load, and peer-driven reorg handling need further campaigns.
Production cost choices require cold-cache and
worst-case block measurements.
