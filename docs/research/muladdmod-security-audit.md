# Experimental `OP_MULADDMOD` Security Assessment and Consensus Audit

- **Repository:** `https://github.com/patrickdugan/bitcoin-rs`
- **Branch:** `feat/experimental-muladdmod`
- **Pull Request:** `https://github.com/patrickdugan/bitcoin-rs/pull/1`
- **Initial PR Commit Audited:** `1fa1ba6ab001e1337f19bb1bf0d614e940501fac` (base `origin/dev`: `9b8e91ae1aadfaad08e7fccbfa895bcbf41c6620`)
- **Machine-Readable Audit Receipt:** [muladdmod-audit-results.json](muladdmod-audit-results.json)
- **Companion Design Notes:** [muladdmod.md](muladdmod.md), [muladdmod-dispute.md](muladdmod-dispute.md)

> **Isolation Warning:** Opcode byte `0xf0` (`OP_SUCCESS240` under BIP 342) has no assigned BIP number, deployment bit, or public-network activation parameters. Every experiment in this campaign ran on isolated loopback regtest networks with synthetic test keys and regtest coinbases. Never fund `0xf0` scripts on mainnet, testnet, or signet.

---

## 1. Executive Summary

This campaign evaluated three questions on `feat/experimental-muladdmod`:

1. **Consensus correctness and isolation:** Does the native `OP_MULADDMOD` (`0xf0`) tapscript implementation satisfy bounded unsigned modular arithmetic semantics, BIP 342 validation-weight accounting, and strict regtest/feature-flag isolation without perturbing legacy Script, SegWit v0, ordinary Taproot, or public-network rules?
2. **Dispute-protocol soundness:** Does the SHA-256-committed, NUMS-locked Taproot arithmetic-claim contract (`muladdmod-dispute.md`) satisfy Safety, Completeness, Exclusivity, Replay Isolation, and Liveness under adversarial transaction construction, mempool conflict, and chain reorganization?
3. **BitVM3 readiness:** Does the provisional 50-unit tapscript validation-weight charge bound worst-case block validation work, and what architectural components remain before `OP_MULADDMOD` can back a production-grade transparent BitVM3 fraud-proof compiler?

### Summary Verdict

| Audit Domain | Verdict | Key Evidence |
| :--- | :--- | :--- |
| **`OP_MULADDMOD` Consensus Arithmetic & Stack Semantics** | **PASS (0 consensus bugs found)** | `12,037` valid + `293` malformed Spiral v0.2 vectors (`0` mismatches); `4,096`-case `proptest` algebraic/width suite (`103/103` script tests); `17/17` non-equivalent source mutants killed (`100%` non-equivalent kill rate). |
| **Activation Boundary & Public-Network Isolation** | **PASS (0 isolation leaks)** | `25,300` randomized differential cases across 12 tapscript shapes + P2WSH + Legacy P2SH (`0` Rust-vs-Python mismatches, `0` soft-fork violations, `0` feature-off binary mismatches); `1,508` Bitcoin Core vector checks; `50` live 3-way cases against `Bitcoin Core v31.1.0` (`0` consensus or policy divergences). |
| **50-Unit Tapscript Budget & Block Validation Bounds** | **PASS (Conservative vs single-sig BIP 340)** | Worst-case 32-byte `OP_MULADDMOD` (`m = 2^256 - 1`, `b = 2^256 - 2`) costs `87.21 us/op` (`1.74 us/unit`), **3.15x cheaper** than single-sig `OP_CHECKSIGVERIFY` (`275.08 us/op`, `5.50 us/unit`). Full ~4M-WU `OP_MULADDMOD` blocks validate in `4.94s` wall (`1` input, `73,845` ops) and `1.08s` wall / `11.54s` CPU (`500` inputs, `70,000` ops) with `<= 150 MB` RSS. |
| **Funded Dispute Protocol (`muladdmod-dispute.md`)** | **CONDITIONALLY SOUND** | `164` adversarial live transactions (`158/158` parity with independent Python `refinterp.py`). Sound **iff** off-chain admission enforces canonical fixed-width operands/modulus and exact `NUMS_X` single-leaf P2TR reconstruction, `recovery_public_key` signs online with `SIGHASH_DEFAULT`/`SIGHASH_ALL`, and `delay > D_reorg + D_censorship`. Six concrete counterexamples (`CE-01`..`CE-06`) confirmed when those assumptions are relaxed. |
| **Node Chainstate, Native ZMQ & CI Infrastructure** | **4 DEFECTS FOUND & FIXED (`DEFECT-01`..`DEFECT-04`)** | Phase 5 bounded state-machine exploration (`1,860` sequences, `7,960` RPC steps) discovered **`DEFECT-01`** (High): `submitblock` and same-second local mining bypassed `NodeStatus::Invalid` header rejection (`0/1,860` post-fix violations). GitHub Actions CI verification surfaced **`DEFECT-03`** (Medium/High): vendored `zeromq-src` (`libzmq 4.3.4`) omitted `HAVE_POSIX_MEMALIGN`, allocating 64-byte-aligned `command_t` pipes via 16-byte `malloc` and crashing `bitcoin-rs-node` (`SIGSEGV` on AVX `vmovdqa` during `SocketZmqPublisher` teardown); fixed via `.cargo/config.toml`. Also fixed workflow branch/concurrency (`DEFECT-02`), invalid YAML scalar in `.github/workflows/main.yml` (`DEFECT-04`), and Rust `1.100.0` Clippy lints. |
| **Production BitVM3 Compiler Readiness** | **PRIMITIVE ONLY (Gaps documented)** | `OP_MULADDMOD` eliminates garbled arithmetic circuits for modular ring/field steps up to 256 bits (`<= 294 B` leaf script), but a complete transparent BitVM3 verifier still requires cross-step state/trace bridging, on-chain encoding-fault challenge branches (or ZK admission proofs), permissionless output covenants/anchors, and public-network soft-fork deployment specification. |

---

## 2. Provenance, Environment, and Phase 1 Evidence Reproduction

### 2.1 Hardware, Toolchain, and Binary Digests

All measurements and live-node experiments ran in an isolated WSL2 environment with DNS seeding disabled and loopback-only RPC/P2P bindings:

- **CPU:** `AMD Ryzen AI 9 365 w/ Radeon 880M` (`20` logical threads, x86_64)
- **Memory & Kernel:** `20,479,880 kB` RAM allocated to WSL2, `Linux 6.18.54.1-microsoft-standard-WSL2` (`glibc 2.39`)
- **Rust Toolchain:** `rustc 1.99.1 (58cf8f9c3 2026-10-13)` (`LLVM 23.1.1`), `cargo 1.99.1 (5f94df478 2026-08-27)`
- **Reference Oracles:** `Python 3.12.3`, `Bitcoin Core daemon version v31.1.0`

| Artifact / Executable | Build Profile & Features | SHA-256 Digest |
| :--- | :--- | :--- |
| `bitcoin-rs-exp-1fa1ba6` | Initial PR `1fa1ba6` (`--release --no-default-features --features fjall,experimental-muladdmod-regtest`) | `a6a3c4eeb3b27018c2c6d558580f34f927134dd248fc522f693e0459c98aface` |
| `bitcoin-rs-exp-fixed` | Patched branch (`--release --no-default-features --features fjall,experimental-muladdmod-regtest`) | `8a9db57972d6bb279dc8d81077e69c3bf72c49aaf8fe0998a0f443e4292d4d0b` |
| `bitcoin-rs-off-fixed` | Patched branch, feature-off (`--release --no-default-features --features fjall`) | `276cb6068c5b1d0823ff13f821da31cdf038086931063d6ae0b956481a5debb7` |
| `script_oracle` | `crates/script/examples/script_oracle.rs` (`--release --features experimental-muladdmod`) | `bc25ba8c907ccd3c8a63ec1358a272f4d6afc5743c8a4c91f60690a5c5db2dcf` |
| `script_oracle_off` | `crates/script/examples/script_oracle.rs` (`--release`, default features off) | `0e2687f6aea47a97c9bdca81b2a999562f683be49da880d17f90cc82a3d745b6` |
| `muladdmod_cost` | `crates/script/examples/muladdmod_cost.rs` (`--release --features experimental-muladdmod`) | `4f96188923d70f0751364476b867b2c8849ad19dd06cc46584c24bd45ec7e07b` |
| `bitcoind` | Official Bitcoin Core `v31.1.0` x86_64 Linux binary | `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08` |

### 2.2 Diff Inspection Against `origin/dev`

Comparing `1fa1ba6ab001e1337f19bb1bf0d614e940501fac` against `origin/dev` (`9b8e91ae1aadfaad08e7fccbfa895bcbf41c6620`) confirmed that the initial PR touched `26` files (`+2,884 / -16` lines) strictly scoped to:

- `crates/script`: `VerifyFlags::EXPERIMENTAL_MULADDMOD` (`1 << 21`), `ScriptError::ExperimentalDisabled` and `ScriptError::MulAddModEncoding`, `muladdmod.rs` (33-byte stack-allocated unsigned little-endian modular fused multiply-add, zero external `bigint` crates), and `eval.rs` (`0xf0` interception in `ScriptVersion::Tapscript` only).
- `crates/consensus`: `experimental-muladdmod-regtest` Cargo feature gating `EXPERIMENTAL_MULADDMOD` strictly to `Network::Regtest` when `taproot` and `witness` deployment heights are active, plus kernel-adapter refusal (`ExperimentalFlagsUnsupported`) so experimental flags can never be masked away by FFI bitmasks.
- `crates/mempool`: inclusion of next-block experimental deployment flags alongside `VerifyFlags::STANDARD`, plus flag-keyed `SigCache` isolation tests.
- `crates/node`: CLI/startup refusal when pairing `--validation-engine kernel` with `experimental-muladdmod-regtest`.
- Mainnet, Testnet3, Testnet4, and Signet consensus flag paths have zero activation route to `VerifyFlags::EXPERIMENTAL_MULADDMOD`.

### 2.3 Phase 1 Test, Lint, Audit, and Fixture Results

| Verification Lane | Runner / Scope | Result | Exact Counts / Details |
| :--- | :--- | :--- | :--- |
| `bitcoin-rs-script` (feature off) | `cargo test --locked -p bitcoin-rs-script` | **PASS** | `81` passed, `0` failed (`3` test binaries) |
| `bitcoin-rs-script` (feature on, baseline -> post-audit) | `cargo test --locked -p bitcoin-rs-script --features experimental-muladdmod` | **PASS** | `96` passed baseline -> `103` passed post-audit (`0` failed) |
| `bitcoin-rs-consensus` (feature on & off) | `cargo test --locked -p bitcoin-rs-consensus [--features experimental-muladdmod-regtest]` | **PASS** | `136` passed on / `136` passed off (`0` failed) |
| `bitcoin-rs-mempool` (feature on) | `cargo test --locked -p bitcoin-rs-mempool --features experimental-muladdmod-regtest` | **PASS** | `476` passed, `0` failed |
| `bitcoin-rs-node` (`muladdmod` + full crate) | `cargo nextest` (`-j 8` clean I/O run) | **PASS** | `383` passed, `0` failed (`muladdmod` integration + new `submission` regression test pass) |
| Workspace Nextest (`10` crates) | `cargo nextest` workspace matrix | **PASS*** | `2,318` passed (`p2p`: `1,407`, `chainstate`: `249`, `primitives`: `120`, `storage`: `71`, `snapshot`: `8`); *`2` I/O-deadline flakes in `node` under 20-way fjall contention passed `383/383` at `-j 8` |
| Chainstate `SYNC-04`/`SYNC-05` prefix proof | `invalid_middle_block_keeps_valid_prefix` + new invalidation proof | **PASS** | `2/2` passed |
| Spiral v0.2 Arithmetic Vectors | Independent Python oracle vs Rust `eval_muladdmod` | **PASS** | `12,037` valid vectors + `293` malformed vectors (`0` mismatches across widths `1..=32`) |
| Formatting, Clippy (`6` lanes), Contract Index | `cargo fmt --check`, `cargo clippy ... -D warnings`, `contract-index --check` | **PASS** | Exit code `0` across all `6` feature combinations and `SYNC-01..SYNC-09` contract index |
| `cargo deny` & `cargo audit` | Dependency license/ban/advisory checks | **PASS / INFO** | `cargo deny`: `rc = 0`. `cargo audit`: `1` pre-existing advisory `RUSTSEC-2026-0418` (`libz-sys 1.1.30` via optional `rocksdb`; not compiled into `fjall` binaries) |
| Python Fixture & Campaign Suites | `unittest` (`scripts/tests`) | **PASS** | `test_muladdmod_claim.py`: `9/9`; repo Python suite: `176/176` (`173` passed, `3` Windows-only skipped); `test_muladdmod_campaign.py`: `13/13` |
| Live Regtest Fixtures (`3` runs) | `muladdmod_rpc.py` + `muladdmod_dispute_rpc.py` (small & wide) | **PASS** | `regtest.json`: `2` rejections, height `102`; `dispute-small.json` (`m = 17`, `263 B` leaf): `19/19` rejections, recovery height `434`, settlement height `439`; `dispute-wide.json` (`m = 2^255 - 19`, `294 B` leaf): `18/18` rejections; all `3` verified `restart_preserved_outputs = true` |

---

## 3. Phase 2: Adversarial Dispute-Contract Campaign

Using `scripts/research/campaign/attacks.py`, we constructed and submitted **`164` live adversarial transactions** against a native `bitcoin-rs` regtest node (`funding_txid = 976db0de47dabf93c16e6cc851c62e0ed1b5d904401257448d7286b01e63db1a` at height `433` after BIP 68/112 activation at height `432`) through both mempool (`testmempoolaccept` + `sendrawtransaction`) and direct block-validation (`submitblock` with synthesized coinbase + witness commitment) paths. Every script-level case was simultaneously evaluated in an independent pure-Python Taproot/Tapscript interpreter (`scripts/research/campaign/refinterp.py`).

### 3.1 Summary & Rejection-Rule Histogram

- **Total live adversarial & control transactions:** `164` (`144` rejected, `20` accepted across valid controls and intentional protocol/operational counterexamples; **`0` unexpected verdicts**).
- **Script-level parity (`refinterp.py` vs native `bitcoin-rs`):** **`158 / 158` exact agreement (`0` disagreements)** across all script-evaluated cases. The remaining `6` transactions terminated at transaction/UTXO/RBF policy layers prior to or independent of Tapscript execution (`non-BIP68-final`, `bad-txns-nonfinal`, `bad-txns-inputs-missingorspent`, `insufficient fee`).

| Consensus / Policy Rule | Count | Representative Adversarial Vectors Rejected |
| :--- | ---: | :--- |
| `SCRIPT_ERR_SCHNORR_SIG` | 48 | Cross-claim signature replay, mutated sighash commitments (value, prevout, output script, fee, annex, key_version), bit-flipped `(R, s)`, operator key in recovery branch, wrong internal/leaf commitment |
| `SCRIPT_ERR_EQUALVERIFY` | 26 | Substituted `a`, `b`, `c`, or `d` preimage; swapped operand stack slots `(b, a, c)`; cross-instance preimage substitution |
| `SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH` | 14 | Modified Tapscript `<modulus>`, modified `<delay>`, stripped `<instance> DROP`, key-path spend with tweaked/untweaked fake key against `NUMS_X`, injected unauthenticated sibling Merkle hash |
| `SCRIPT_ERR_UNSATISFIED_LOCKTIME` | 12 | `nSequence` disable flag (`1 << 31`), time-based CSV flag (`1 << 22`) against block-locked CSV, `tx.version = 1` with CSV, `nSequence < delay` |
| `SCRIPT_ERR_SCHNORR_SIG_HASHTYPE` | 8 | Invalid hashtype bytes (`0x04`, `0x05`, `0x80`, `0xff`) |
| `SCRIPT_ERR_TAPSCRIPT_MINIMALIF` | 8 | Branch selector `0x02`, `0x0001`, `0x80` (`-0`), `0x0100` on `OP_IF` |
| `SCRIPT_ERR_EVAL_FALSE` | 5 | Honest-claim fraud recovery attempt (`(a * b + c) mod m == d` -> `OP_EQUAL OP_NOT` pushes `""`), bad operator sig in `OP_CHECKSIG` (`ELSE` branch) |
| `SCRIPT_ERR_MULADDMOD_ENCODING` | 4 | Recovery witness preimage matching `H(x)` on a malformed-admission output (`a >= m`, wrong byte width, `m = 1`, non-minimal `m` with `0x00` MSB) |
| `SCRIPT_ERR_SCHNORR_SIG_SIZE` | 4 | `63`-byte, `66`-byte, empty recovery sig (`CHECKSIGVERIFY` path), `64`-byte + trailing garbage |
| `SCRIPT_ERR_CHECKSIGVERIFY` | 2 | Empty byte vector `""` supplied to `<recovery_pk> OP_CHECKSIGVERIFY` |
| `SCRIPT_ERR_CLEANSTACK` | 2 | Extra witness element under `IF` or `ELSE` branch |
| `SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE` | 2 | `32`-byte truncated control block, `34`-byte unaligned control block |
| Non-Script Consensus / Policy | 9 | `non-BIP68-final` / `bad-txns-nonfinal` (premature settlement before `delay` blocks), `bad-txns-inputs-missingorspent` (recovery after settlement or settlement after recovery), `insufficient fee` (underpaying RBF conflict) |

### 3.2 Independently Confirmed Protocol & Operational Counterexamples

While the `OP_MULADDMOD` consensus opcode behaved exactly as specified on every transaction, Phase 2 confirmed **six distinct protocol-level and operational counterexamples** against naive deployments of the one-step dispute contract (`muladdmod-dispute.md`):

1. **`CE-01` -- Admission-Bypass Safety Violation (`noncanonical_d_congruent_claim_confiscated`):**
   - *Mechanism:* Suppose `m = 17` (`0x11`), `(7 * 11 + 3) mod 17 = 12` (`0x0c`), and an operator publishes an arithmetically honest claim `d == 12 (mod 17)` encoded non-canonically as 1-byte `0x1d` (`29 == 12 mod 17`) or 2-byte `0x0c00`, committing `H(d)` in the leaf without funder preimage validation.
   - *Live Result:* **ACCEPTED by consensus.** `OP_MULADDMOD` validates only `(a, b, c, m)` and pushes canonical 1-byte `0x0c`. Byte-wise `OP_EQUAL` compares `0x0c` against `0x1d` (or `0x0c00`), evaluates `false`, and `OP_NOT` evaluates **`true`**, allowing `recovery_public_key` to confiscate an integer-congruent claim.
2. **`CE-02` -- Admission-Bypass Completeness Violation (`false_claim_oversized_operand_settles`, `false_claim_nonminimal_modulus_settles`):**
   - *Mechanism:* If a funder locks funds into a claim leaf where `H(a)` commits to a preimage `a >= m` or wrong byte width (or `<modulus>` is `0`, `1`, or padded with a trailing `0x00`), `OP_MULADDMOD` aborts the entire transaction with `SCRIPT_ERR_MULADDMOD_ENCODING` instead of pushing a failure flag onto the stack.
   - *Live Result:* **Recovery REJECTED (`SCRIPT_ERR_MULADDMOD_ENCODING`); Operator Settlement ACCEPTED after `delay` blocks.** Fraud becomes unchallengeable on-chain because the `IF` branch cannot terminate cleanly, whereas the `ELSE` (`CSV + operator CHECKSIG`) branch never executes `OP_MULADDMOD`.
3. **`CE-03` -- Unverified Taproot Tree / Internal Key Bypass (`operator_backdoor_leaf_in_unverified_tree`, `operator_internal_key_keypath_bypass`):**
   - *Mechanism:* If a verifier checks the arithmetic `TapLeaf` source text without reconstructing the tweaked P2TR output key `Q = P + H_TapTweak(P || merkle_root) * G` from `P = NUMS_X` and a single-leaf root, the operator can either substitute a known internal key `P'` (spending immediately at height `funding + 1` via key-path, bypassing `CSV` and `OP_MULADDMOD`) or attach a sibling `<operator_pk> OP_CHECKSIG` leaf.
   - *Live Result:* **ACCEPTED by consensus** when funded to the unverified P2TR key; prevented strictly by deterministic off-chain reconstruction of `scriptPubKey`.
4. **`CE-04` -- Unconstrained Recovery Destination & Non-Permissionless Challenger (`third_party_redirects_sighash_none_recovery`):**
   - *Mechanism:* The `IF` branch enforces `<recovery_pk> OP_CHECKSIGVERIFY` with no output covenant (`OP_CTV`/`SIGHASH_SINGLE` template) and requires a live signature from the single `recovery_secret` holder. If that holder signs with `SIGHASH_NONE` (`0x02`) or `SIGHASH_ANYONECANPAY | SIGHASH_NONE` (`0x82`), any relay/miner can rewrite the transaction outputs and sweep the recovered collateral; conversely, if `recovery_secret` is offline, third-party watchtowers with full fraud witnesses cannot challenge.
   - *Live Result:* **Redirected `SIGHASH_NONE` recovery ACCEPTED by consensus.**
5. **`CE-05` -- Full-RBF Fee Preemption & `delay = 1` Zero-Margin Window (`settlement_outbids_recovery_rbf`, `delay1_settlement_valid_next_block`):**
   - *Mechanism:* `bitcoin-rs` enforces full-RBF in mempool conflict resolution even when `recovery` sets `nSequence = 0xffffffff`. Once block height reaches `funding_height + delay - 1` (so settlement is BIP 68-final for the next block), an operator settlement paying a higher fee/feerate evicts an unconfirmed recovery transaction directly from the mempool. Furthermore, setting `delay = 1` makes settlement valid in block `funding_height + 1` (the exact first block after confirmation), leaving **zero blocks** in which recovery is exclusively valid.
   - *Live Result:* **Higher-fee settlement ACCEPTED into mempool, evicting unconfirmed recovery; `delay = 1` settlement confirmed in `funding_height + 1`.**
6. **`CE-06` -- Challenge-Deadline Reorganization Reversal (`reorg14_settlement_on_fork_after_recovery_was_disconnected`):**
   - *Mechanism:* A challenger confirms `recovery` at `funding_height + 1`. An adversarial miner privately mines a competing fork of length `>= delay` omitting `recovery`, includes `settlement` once `CSV` matures on the private branch, and broadcasts the heavier chain.
   - *Live Result:* **Competing fork ACCEPTED; `recovery` rolled back, `settlement` confirmed, and `recovery` permanently evicted (`bad-txns-inputs-missingorspent`).**

---

## 4. Phase 3: Consensus Differential Testing and Activation Isolation

### 4.1 Randomized Differential Fuzzing (`25,300` Cases)

`scripts/research/campaign/differential.py` generated **`25,300` randomized script/witness/context test cases** across 4 deterministic seeds (`seed = 1`: `300`; `seed = 42` with `--oracle-off`: `5,000`; `seed = 7`: `10,000`; `seed = 20261112`: `10,000`), spanning:

- **3 Script families:** Tapscript (`22,821` cases), SegWit v0 P2WSH (`1,214` cases), and Legacy P2SH (`1,265` cases).
- **12 Tapscript structural templates:** `plain`, `if_exec`, `if_skip`, `else`, `nested`, `underflow`, `budget`, `sig`, `stack` (`999..1002` witness items), `element` (`519..522`-byte pushes), `success` (co-occurring `OP_SUCCESS80`/`0xbb`/`0xef`/`0xf1`/`0xfe`), and `multi` (chained arithmetic).

Every case was evaluated under 4 flag regimes (`consensus_off`, `consensus_on`, `policy_off`, `policy_on`) in both Rust (`script_oracle`) and independent Python (`refinterp.py`), plus `5,000` cases cross-checked against the feature-disabled Rust binary (`script_oracle_off`):

- **Rust vs Python mismatches (flag on & flag off):** **`0 / 25,300`**
- **Error-code mismatches (flag on):** **`0 / 25,300`**
- **Soft-fork directionality violations (`accept_on == true` while `accept_off == false`):** **`0 / 25,300`** (`11,746` cases tightened from `OP_SUCCESS240` unconditional accept to `OP_MULADDMOD` arithmetic/stack/budget enforcement; `0` loosened)
- **Feature-off binary isolation mismatches (`script_oracle_off`):** **`0 / 5,000`** (requesting `VerifyFlags::EXPERIMENTAL_MULADDMOD` without the Cargo feature deterministically fails closed with `SCRIPT_ERR_EXPERIMENTAL_DISABLED`)

### 4.2 Complete `OP_SUCCESS240` Activation-Boundary Matrix

| Boundary Condition | Pre-Activation (`EXPERIMENTAL_MULADDMOD = 0`) | Activated (`EXPERIMENTAL_MULADDMOD = 1` in Tapscript) | Verified By |
| :--- | :--- | :--- | :--- |
| Pushdata containing byte `0xf0` | Parsed as literal push byte; not `OP_SUCCESS` | Parsed as literal push byte; no arithmetic triggered | `muladdmod.rs`, `differential.py` (`element`) |
| `0xf0` in unexecuted `OP_IF 0 ... OP_ENDIF` branch | Pre-execution scan triggers immediate `OP_SUCCESS` return | **Loses early-success return**; skipped at runtime with **`0` budget debit** and **`0` encoding checks** | `activated_opcode_loses_early_success_bypass`, `differential.py` (`if_skip`) |
| Initial witness stack `> 1,000` items + `0xf0` | Pre-scan `OP_SUCCESS` bypasses `1,000`-item stack check (BIP 342) | **Fails closed with `StackSize`** before execution | `activated_opcode_loses_early_success_bypass`, `differential.py` (`stack`) |
| Witness item `> 520` bytes + `0xf0` | Pre-scan `OP_SUCCESS` bypasses `520`-byte push check | **Fails closed with `PushSize`** | `differential.py` (`element`) |
| Validation-weight initialization | N/A on `OP_SUCCESS` | `50 + witness_serialized_size(witness)` including CompactSize prefixes and BIP 341 `0x50` annex | `witness_serialization_and_annex_determine_the_shared_budget` |
| Stack `< 4` items before `0xf0` | Immediate `OP_SUCCESS` | `InvalidStackOperation` checked **before** `50`-unit budget debit | `three_item_stack_underflow_precedes_budget_exhaustion` (`M13` test) |
| Other `OP_SUCCESSx` (`0x50`, `0x89`, `0xef`, `0xf1..0xfe`) | Unconditional `OP_SUCCESS` (consensus) / `DiscourageOpSuccess` (policy) | **Unchanged**; if `0xf1` appears anywhere in the script, `0xf1`'s pre-scan still succeeds early | `other_op_success_opcodes_keep_early_success_and_policy_discouragement` |
| Legacy `scriptSig`/`P2SH` and SegWit v0 `P2WSH` with `0xf0` | Fails with `BadOpcode` (`0xf0 > OP_NOP10`) | **Unchanged** (`BadOpcode`); `EXPERIMENTAL_MULADDMOD` is consulted only for `ScriptVersion::Tapscript` | `legacy_and_witness_v0_keep_their_previous_opcode_rules`, mutant `M11` |
| `MINIMALIF` & ScriptNum `-0` (`0x80`) | Standard BIP 342 | `OP_MULADDMOD` outputs fixed-width unsigned LE (`0x0100` for `1` at width `2`, failing `MINIMALIF` if fed directly to `OP_IF`; `0x80 == 128`, not `-0`) | `fixed_width_one_does_not_bypass_minimalif`, `unsigned_negative_zero_requires_an_explicit_comparison` |
| `SigCache` / execution-cache isolation | Cached under flags without bit `21` | Keyed by full `VerifyFlags::bits()`; flag-off `OP_SUCCESS` entry never satisfies flag-on verification | `crates/mempool` `muladdmod` cache regression |

### 4.3 Bitcoin Core Test Vectors & Live 3-Way Differential (`Bitcoin Core v31.1.0`)

1. **Bitcoin Core Static Vectors (`crates/script/tests/core_vectors.rs`):** Evaluated **`1,508` valid/invalid test vectors** imported from Bitcoin Core (`script_tests.json`, `tx_valid.json`, `tx_invalid.json`) with `VerifyFlags::EXPERIMENTAL_MULADDMOD` toggled off vs on. Result: **`1,508 / 1,508` identical verdicts and error codes** (`0` regressions).
2. **Live 3-Way Node Campaign (`scripts/research/campaign/core_diff.py`):** Launched **`bitcoin-rs-exp-fixed`**, **`bitcoin-rs-off-fixed`**, and **`Bitcoin Core v31.1.0`** (`bitcoind -regtest`) side-by-side and submitted **`50` ordinary transactions and blocks** covering Legacy P2PKH (`4`), P2SH (`10`, including `0xf0` inside P2SH), SegWit v0 P2WPKH/P2WSH (`9`, including `0xf0` inside P2WSH), Taproot key-path (`5`), and non-`0xf0` Tapscript (`22`, covering `CHECKSIG`, `CHECKSIGADD`, validation-weight exhaustion, `MINIMALIF`, `CLEANSTACK`, `OP_SUCCESS80`/`OP_SUCCESS241`, `CSV`, `CLTV`, annexes, and bad control blocks):
   - **Block-validation verdicts:** `23` accepted, `27` rejected -- **`0` consensus mismatches** across all 3 nodes.
   - **Mempool admission (`testmempoolaccept`):** **`0` policy differences** across all 3 nodes (`OP_SUCCESS80` and `OP_SUCCESS241` rejected by policy on all 3; accepted in mined blocks on all 3).
   - **Final chain tips:** Identical across all 3 implementations (`330593d81fd646a3ec90970631f6cedbae303f34f2808fcd2f3b2b38be449160`).

---

## 5. Phase 4: Worst-Case Computational Costs and 50-Unit Budget Assessment

### 5.1 Microbenchmarks Across Widths `1..=32` (`crates/script/examples/muladdmod_cost.rs`)

Measured in release mode (`k = 2,000` chained operations per tapscript evaluation, median of `15` repetitions; `b = 2^(8w) - 2` all-ones bit pattern maximizes inner modular shift-add reductions):

| Benchmark Class / Operand Width | Modulus `m` | Median `ns / op` | `ns / budget unit` (`50` units) | Relative Cost vs `OP_CHECKSIGVERIFY` |
| :--- | :--- | ---: | ---: | ---: |
| `OP_MULADDMOD` width `1` (prime) | `17` (`0x11`) | `1,374.7` | `27.49` | `0.0050x` (`200.1x` faster) |
| `OP_MULADDMOD` width `1` (composite) | `15` (`0x0f`) | `1,425.2` | `28.50` | `0.0052x` (`193.0x` faster) |
| `OP_MULADDMOD` width `1` (max) | `255` (`0xff`) | `2,530.5` | `50.61` | `0.0092x` (`108.7x` faster) |
| `OP_MULADDMOD` width `2` (max) | `2^16 - 1` | `7,211.8` | `144.24` | `0.0262x` (`38.1x` faster) |
| `OP_MULADDMOD` width `4` (max) | `2^32 - 1` | `11,124.6` | `222.49` | `0.0404x` (`24.7x` faster) |
| `OP_MULADDMOD` width `8` (max) | `2^64 - 1` | `20,387.2` | `407.74` | `0.0741x` (`13.5x` faster) |
| `OP_MULADDMOD` width `12` (max) | `2^96 - 1` | `26,832.2` | `536.64` | `0.0975x` (`10.3x` faster) |
| `OP_MULADDMOD` width `16` (max) | `2^128 - 1` | `43,842.5` | `876.85` | `0.1594x` (`6.27x` faster) |
| `OP_MULADDMOD` width `20` (max) | `2^160 - 1` | `29,488.2` | `589.76` | `0.1072x` (`9.33x` faster) |
| `OP_MULADDMOD` width `24` (max) | `2^192 - 1` | `39,980.6` | `799.61` | `0.1453x` (`6.88x` faster) |
| `OP_MULADDMOD` width `28` (max) | `2^224 - 1` | `78,505.4` | `1,570.11` | `0.2854x` (`3.50x` faster) |
| `OP_MULADDMOD` width `31` (max) | `2^248 - 1` | `78,579.5` | `1,571.59` | `0.2857x` (`3.50x` faster) |
| `OP_MULADDMOD` width `32` (min MSB `0x01`) | `2^248` | `39,538.7` | `790.77` | `0.1437x` (`6.96x` faster) |
| `OP_MULADDMOD` width `32` (Curve25519 prime) | `2^255 - 19` | `81,439.6` | `1,628.79` | `0.2961x` (`3.38x` faster) |
| **`OP_MULADDMOD` width `32` (Worst-Case)** | **`2^256 - 1`** | **`87,207.2`** | **`1,744.14`** | **`0.3170x` (`3.15x` faster)** |
| **BIP 340 `OP_CHECKSIGVERIFY` (`50` units)** | secp256k1 | **`275,083.3`** | **`5,501.67`** | **`1.0000x` (baseline)** |
| Mixed (`OP_MULADDMOD` w32 + `OP_CHECKSIGVERIFY`, `100` units) | `2^256 - 1` + sig | `368,436.7` / pair | `3,684.37` | `0.6697x` per unit |
| Unpriced `OP_DUP OP_SHA256 OP_DROP` (`520 B`, `0` units) | SHA-256 (`3` script B) | `838.4` | `279.48 ns / WU` | Paid solely by `3` witness bytes |

*Full width `1..=32` measurements (`64` rows, both `max_modulus_b_all_ones` and `min_top_byte_modulus`) are recorded in [muladdmod-audit-results.json](muladdmod-audit-results.json).*

### 5.2 Adversarial ~4,000,000-Weight Full-Block Benchmarks (`scripts/research/campaign/blockbench.py`)

How dense can `OP_MULADDMOD` operations be packed into a 4,000,000-WU block? Each executed operation requires at least `1` byte (`0xf0`) in the tapscript plus operands/stack setup (`DUP DUP DUP <m> OP_MULADDMOD` = `37 B` per op inline, or `DUP TOALTSTACK ...` loops = `4..6 B` per op amortized) AND `50` validation-weight units funded by `witness_bytes` at `1 WU = 1 budget unit`. Thus a `4,000,000`-WU block has a hard ceiling of:

$$\text{Max operations per block} \le \left\lfloor \frac{4{,}000{,}000 + 50 \cdot N_{\text{in}}}{50 + \text{bytes\_per\_op}} \right\rfloor \approx 73{,}845 \text{ ops (1 input)} \;\text{to}\; 70{,}000\text{--}74{,}000 \text{ ops (500 inputs)}$$

Using a BIP 341 annex (`0x50 || padding`) to supply pure witness weight at `1` byte per unit alongside compact `DUP`-fed arithmetic loops, we constructed and validated `10` full-block templates via live `submitblock` RPC (measuring wall-clock latency, `/proc/<pid>/stat` user+sys CPU ticks, and `/proc/<pid>/status` peak RSS `VmHWM`):

| Block Template | Inputs | Total Ops | Tx Weight (WU) | Median Wall (s) | Node CPU (s) | Peak `VmHWM` (kB) | Accepted |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| `baseline_annex_only_1in` | 1 | 0 | `3,988,046` | `0.1608` | `0.11` | `144,556` | Yes |
| `muladdmod_w1_composite_1in` (`m = 15`) | 1 | `73,845` | `3,988,072` | `0.2644` | `0.19` | `149,968` | Yes |
| `muladdmod_w16_max_1in` (`m = 2^128 - 1`) | 1 | `73,845` | `3,988,132` | `2.1701` | `2.12` | `149,968` | Yes |
| `muladdmod_p25519_1in` (`m = 2^255 - 19`) | 1 | `73,845` | `3,988,196` | `5.3332` | `5.25` | `149,968` | Yes |
| **`muladdmod_w32_max_1in` (`m = 2^256 - 1`)** | **1** | **`73,845`** | **`3,988,196`** | **`4.9437`** | **`4.90`** | **`149,968`** | **Yes** |
| **`muladdmod_w32_max_500in` (`m = 2^256 - 1`)** | **500** | **`70,000`** | **`3,954,222`** | **`1.0842`** | **`11.54`** | **`149,968`** | **Yes** |
| `mixed_arith_schnorr_500in` (`34.5k` + `34.5k`) | 500 | `69,000` | `3,984,222` | `0.9608` | `14.01` | `149,968` | Yes |
| `schnorr_500in` (`OP_CHECKSIGVERIFY`) | 500 | `73,000` | `3,952,722` | `1.0354` | `16.32` | `149,968` | Yes |
| `mixed_arith_schnorr_1in` (3.65 MB annex)* | 1 | `73,166` | `3,988,212` | `188.1961` | `189.23` | `142,336` | Yes |
| `schnorr_1in` (3.85 MB annex)* | 1 | `76,685` | `3,988,151` | `402.7738` | `405.34` | `133,068` | Yes |

*\*Discovery of Pre-Existing Tapscript Issue `PERF-01`:* In `schnorr_1in` (`1` input, `76,685` `OP_CHECKSIGVERIFY` ops funded by a `3.85 MB` BIP 341 annex), block validation took **`402.77s`** (`405.34s` CPU) because `bitcoin-rs-script`'s Taproot sighash implementation recomputes `SHA256(compact_size(annex) || annex)` on every signature check rather than caching `sha_annex` per input (`76,685 * 3.85 MB ~= 295 GB` of SHA-256). By contrast, `muladdmod_w32_max_1in` with the same `3.85 MB` annex took **`4.94s`** because `OP_MULADDMOD` performs zero sighash hashing. Across realistic multi-input blocks (`500` inputs, parallelized across rayon worker threads), 32-byte `OP_MULADDMOD` (`1.08s` wall / `11.54s` CPU) is strictly faster than `schnorr_500in` (`1.04s` wall / `16.32s` CPU) and adds zero heap growth (`VmHWM = 149.97 MB`, matching stack-only `[u8; 33]` design).

### 5.3 Adequacy of the 50-Unit Charge and Measured Recommendation

1. **Current DoS Verdict -- SAFE:** Under individual BIP 340 verification, worst-case 256-bit `OP_MULADDMOD` (`87.21 us/op`, `4.90s` single-core block CPU, `1.08s` 20-thread wall time on 500 inputs) is **3.15x cheaper per budget unit** than `OP_CHECKSIGVERIFY` (`275.08 us/op`, `16.32s` block CPU on 500 inputs) and **6.4x cheaper per witness byte** than unpriced `OP_DUP OP_SHA256 OP_DROP` chains (`279.48 ns/WU` vs `1,744.14 ns/WU` for 1-unit-per-WU `OP_MULADDMOD` density, or comparable within constant factors). A `50`-unit charge prevents computational denial of service on current hardware.
2. **Batch-Verification & Algorithmic Nuance:**
   - Unlike BIP 340 Schnorr signatures -- which admit future cross-input half-aggregation or Strauss/Pippenger batch verification (`~4x-8x` speedup, lowering amortized signature cost to `~35-70 us/sig`) -- data-dependent `OP_MULADDMOD` chains (`x_{i+1} = (x_i * a + c) mod m`) are **inherently sequential within an input** and cannot be batch-verified.
   - The current `crates/script/src/muladdmod.rs` implementation uses a deliberately simple, auditable byte-by-byte / bit-by-bit shift-and-subtract loop (`256` outer bit iterations over `33`-byte slices at `w = 32`), producing a `34.5x` spread between 1-byte (`2.53 us`) and 32-byte (`87.21 us`) execution.
3. **Measured Recommendation for Production Soft-Fork Specification:**
   - **Preferred path (keep flat `50`-unit consensus rule, optimize implementation):** Retain the flat **`50`-unit charge** in consensus (preserving BIP 342's simple single-counter model), and replace the internal byte-loop in `muladdmod.rs` with fixed `[u64; 4]` -> `[u64; 8]` limb schoolbook multiplication (`16` `u64 x u64 -> u128` mul-adds) + Knuth Algorithm D division (`crates/script/src/muladdmod/tests.rs` already contains a reference `u64`-limb Knuth D oracle used by our proptests). On x86_64/AArch64, limb arithmetic reduces 32-byte `OP_MULADDMOD` from `~87 us` to **`< 4 us` (`> 20x` speedup)**, making `50` units **`> 10x` cheaper than even batch-verified Schnorr**.
   - **Alternative path (if retaining the byte-by-byte reference loop verbatim):** If an implementation deliberately avoids `u64`/`u128` limb division, a width-affine charge `cost(w) = 16 + 2 * w` (`18` units at `w = 1` up to `80` units at `w = 32`) equalizes CPU time per budget unit (`<= 1,090 ns/unit`) below batched Schnorr (`~1,100 ns/unit` at `55 us / 50`).

---

## 6. Phase 5: BitVM Security Properties, State-Machine Exploration, and Mutation Testing

### 6.1 Explicit Separation of Cryptographic Assumptions vs Verified Properties

| Layer | Status | Statement |
| :--- | :--- | :--- |
| **Cryptographic Assumption `CA-1` (SHA-256)** | Assumed (Standard) | SHA-256 is collision-, preimage-, and second-preimage-resistant; an adversary cannot find `x' != x` with `SHA256(x') == H(x)`. |
| **Cryptographic Assumption `CA-2` (BIP 340 Schnorr)** | Assumed (Standard) | BIP 340 Schnorr over secp256k1 is EUF-CMA secure under the Algebraic Group Model + Random Oracle Model. |
| **Cryptographic Assumption `CA-3` (BIP 341 NUMS)** | Assumed (Standard) | No party knows `x` such that `x * G = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)`. |
| **Admission Precondition `AP-1`** | Caller Obligation (Falsified if omitted: `CE-01..CE-03`) | Before funding, the verifier reconstructs the exact single-leaf `NUMS_X` P2TR `scriptPubKey` and verifies `m in [2, 2^256 - 1]` minimal LE and `a, b, c, d in [0, m - 1]` of width `len(m)`. |
| **Invariant 1: Safety** | **Verified (`proptest` + `attacks.py` + `statemachine.py`)** | Under `CA-1..CA-3` + `AP-1`, **no transaction spending the `IF` (recovery) branch is consensus-valid when `(a * b + c) mod m == d`**. |
| **Invariant 2: Completeness** | **Verified (`proptest` + `attacks.py` + `statemachine.py`)** | Under `AP-1`, **every canonical tuple with `(a * b + c) mod m != d` admits a deterministic valid witness `[a, b, c, d, sig_recovery, 0x01, leaf, ctrl]`** within budget (`1` sig + `1` `OP_MULADDMOD` = `100` units <= `50 + witness_size`). |
| **Invariant 3: Exclusivity** | **Verified (`statemachine.py` + `reorg.py`)** | Recovery and settlement spend the identical UTXO `(txid_fund, vout)`; UTXO consumption ensures **at most one can exist on any valid chain**, including across arbitrary reorganizations. |
| **Invariant 4: Replay Isolation** | **Verified (`proptest` + `attacks.py`)** | Under `CA-1..CA-2` and `SIGHASH_DEFAULT`/`SIGHASH_ALL`, BIP 341 sighash commits `sha_prevouts`, `sha_amounts`, `sha_scriptpubkeys`, `sha_sequences`, `sha_outputs`, and `tapleaf_hash` (containing `<instance>`), preventing cross-claim signature or witness substitution. |
| **Invariant 5: Liveness** | **Conditional (`CE-05`, `CE-06`)** | Holds **only** under (a) online `recovery_secret` signer, (b) fee-bumping sufficiency against unrelated congestion during `[funding + 1, funding + delay - 1]`, (c) `delay >= 2` (`delay = 1` gives `0` exclusive blocks), and (d) maximum adversarial reorg depth `< delay`. |

### 6.2 Property-Based Testing (`4,096` Cases / Property)

Added `proptest` suites in `crates/script/src/muladdmod/tests.rs` and `crates/script/tests/muladdmod.rs` (`PROPTEST_CASES=4096`):

1. `canonical_operands_match_limb_reference_across_all_widths`: `4,096` random widths `1..=32`, moduli `2..=2^256 - 1` (including composite and MSB-heavy moduli), and canonical `(a, b, c)` compared against an independent `[u64; 5]` Knuth Algorithm D Euclidean division oracle (`0` failures).
2. `ring_identities_commutativity_and_distributivity_hold`: verifies `(a * b + c) == (b * a + c) (mod m)`, additive identity `c = 0`, multiplicative identity `b = 1`, annihilator `b = 0`, and modular distributivity `((a1 + a2) * b + c) == ((a1 * b) + (a2 * b + c)) (mod m)` (`0` failures).
3. `non_canonical_widths_and_residues_always_reject`: random width mutations, trailing-zero moduli, `m in {0, 1}`, and `x >= m` (`0` false accepts).
4. `canonical_dispute_safety_completeness_and_replay_isolation`: full Taproot transaction construction and native script verification across random widths `1..=32`, proving honest claims reject recovery (`EvalFalse`), dishonest claims accept recovery, wrong-instance witnesses reject (`WitnessProgramMismatch` / `SchnorrSig`), and mutated preimages reject (`EqualVerify`) (`0` failures).

### 6.3 Bounded State-Machine Exploration & Discovery of `DEFECT-01`

`scripts/research/campaign/statemachine.py` executed **`1,860` transition sequences (`7,960` live RPC steps)** against `bitcoin-rs` for both honest and fraudulent claims (`delay = 2`), combining **all exhaustive sequences of length `1..=4`** (`5 + 25 + 125 + 625 = 780` x `2` claim types = `1,560`) plus **`300` randomized depth-7 sequences** over alphabet:

- `M`: mine next block (`generatetoaddress`)
- `E`: mine empty coinbase-only block (`submitblock` bypassing mempool, modeling miner censorship)
- `R`: broadcast valid/attempted fraud recovery (`sendrawtransaction`)
- `S`: broadcast delayed operator settlement (`sendrawtransaction`)
- `X`: invalidate current tip (`invalidateblock` / reorg rollback)

#### Discovery of `DEFECT-01` (Pre-Fix Binary `a6a3c4ee...`)

On sequence **`EXMERSM` (`honest = True`, `funding_height = 4895`)**, the state-machine oracle flagged `MODEL` and `TIMELOCK` invariant violations (`settlement` accepted into mempool at reported height `4893` and mined at `4894 < 4895 + 2`!). Root-cause investigation uncovered a **High-severity chainstate/mining bug (`DEFECT-01`)** in `bitcoin-rs`:

1. At height `4895` (`funding`), action `E` submitted an empty block `B_4896` via `submitblock` (`timestamp = T`, `nonce = 0`), advancing tip to `4896`.
2. Action `X` called `invalidateblock` down to height `4891`, marking `B_4892 .. B_4896` with `NodeStatus::Invalid` in `HeaderIndex` while disconnecting them from `Chainstate`.
3. Immediately within the **same Unix second `T`**, actions `M` and `E` mined empty blocks starting from `4891` with `nonce = 0`, deterministically reproducing the exact block hashes `B_4892 .. B_4895` that had just been marked `NodeStatus::Invalid`!
4. Two missing guards interacted:
   - `MiningCoordinator::submit` (`crates/node/src/mining.rs`) checked `Chainstate::contains_block(&hash)` (returning `Duplicate`) **without** checking `HeaderIndex::node(&hash).status == NodeStatus::Invalid` (failing to return BIP 22 `"duplicate-invalid"`), and `MiningCoordinator::generate_one` started `nonce` at `0` without skipping hashes already present in `HeaderIndex`.
   - `validate_contextual_block_header` (`crates/chainstate/src/connect.rs`) checked `parent_node` height/bits/timestamp **without** rejecting `existing.status == NodeStatus::Invalid` or `parent_node.status == NodeStatus::Invalid`, and `HeaderIndex::insert_header` preserved sticky `NodeStatus::Invalid` while `HeaderIndex::record_valid_block_index` refused to clear `NodeStatus::Invalid`.
5. Consequently, `Chainstate` re-connected the invalidated blocks while `HeaderIndex` silently propagated `NodeStatus::Invalid` to **every subsequent descendant block on the active chain**, desynchronizing `HeaderIndex::best_header` (`4891`) from `Chainstate::tip` (`4895+`) and corrupting mempool/RPC height views!

#### Fix and Post-Fix Verification (`8a9db579...`)

- **Fix in `crates/chainstate/src/connect.rs`:** `validate_contextual_block_header` now rejects any header whose own `HeaderIndex` entry or parent entry has `NodeStatus::Invalid` (`ValidationError::KnownInvalidHeader { hash }`).
- **Fix in `crates/node/src/mining.rs`:** `MiningCoordinator::submit` checks `header_index.node(&block_hash)` up front and returns `SubmitOutcome::DuplicateInvalid` when `status == NodeStatus::Invalid`; `generate_one` skips any candidate `block_hash` already recorded in `HeaderIndex`.
- **Regression tests added:**
  - `crates/chainstate/src/connect/tests.rs::invalidated_header_and_invalid_parent_cannot_validate_or_commit`
  - `crates/node/tests/mining/submission.rs::submit_and_generate_refuse_invalidated_blocks_and_mine_distinct_replacements`
- **Post-fix state-machine rerun (`phase5-fixed/phase5-statemachine.json`):** Executed all **`1,860` sequences (`7,960` RPC steps, `165` confirmed recoveries, `101` confirmed settlements)** against `bitcoin-rs-exp-fixed` -> **`0` violations**!

### 6.4 Source-Mutation Campaign (`18` Mutants)

`scripts/research/campaign/mutation.py` applied **`18` targeted single-fault source mutants** across `crates/script/src/muladdmod.rs`, `crates/script/src/eval.rs`, and `crates/script/src/interpreter.rs`:

- **Mutants applied:** `18 / 18`
- **Non-equivalent mutants killed:** **`17 / 17` (`100.0%` non-equivalent kill rate; `94.4%` raw score)**
- **Equivalent mutant (`M14`):** Swapping `a` and `b` in `eval_muladdmod(&a, &b, &c, &m)` (`eval.rs`) is mathematically equivalent because both `a` and `b` are validated to identical width `len(m)` and `< m`, and integer multiplication commutes (`a * b + c == b * a + c`). (Operand commitment order `<H(a)>` vs `<H(b)>` in the dispute script happens *before* `OP_MULADDMOD` and is verified by `operand_slot_swap`.)
- *Audit improvement during campaign:* Mutant `M13` (`self.stack.len() < 4` -> `< 3` in `eval.rs`) initially survived when tested with sufficient validation budget because `pop_bytes` caught the underflow 2 lines later; adding `three_item_stack_underflow_precedes_budget_exhaustion` in `crates/script/src/eval/muladdmod_tests.rs` locked down error precedence (`InvalidStackOperation` before `TapscriptValidationWeight`) and killed `M13`.

| ID | File | Fault Injected | Status | Killing Test(s) |
| :--- | :--- | :--- | :---: | :--- |
| `M01` | `muladdmod.rs` | Charge `49` units instead of `50` | **Killed** | `exact_budget_is_debited_and_missing_budget_fails` |
| `M02` | `muladdmod.rs` | Charge `0` units | **Killed** | `exact_budget_is_debited_and_missing_budget_fails` |
| `M03` | `muladdmod.rs` | Accept modulus `0` or `1` | **Killed** | `independent_spiral_vectors_cover_every_width_...` |
| `M04` | `muladdmod.rs` | Accept non-minimal modulus (trailing `0x00`) | **Killed** | `independent_spiral_vectors_cover_every_width_...` |
| `M05` | `muladdmod.rs` | Accept residue `x == m` (`!= Greater` instead of `!= Less`) | **Killed** | `independent_spiral_vectors_cover_every_width_...` |
| `M06` | `muladdmod.rs` | Skip conditional subtraction when `acc == m` | **Killed** | `maximum_width_carry_is_reduced_without_truncation` (+2) |
| `M07` | `muladdmod.rs` | Drop bit `0` in inner bit loop (`(1..8).rev()`) | **Killed** | `canonical_operands_match_limb_reference_...` (+5) |
| `M08` | `muladdmod.rs` | Ignore addend `c` | **Killed** | `ring_identities_commutativity_and_distributivity_hold` (+4) |
| `M09` | `muladdmod.rs` | Reject 32-byte moduli (`> 31`) | **Killed** | `maximum_width_carry_is_reduced_without_truncation` (+3) |
| `M10` | `muladdmod.rs` | Drop multi-byte carry propagation in `add_assign_le` | **Killed** | `maximum_width_carry_is_reduced_without_truncation` (+3) |
| `M11` | `eval.rs` | Execute `OP_MULADDMOD` in Legacy / SegWit v0 | **Killed** | `legacy_and_witness_v0_keep_their_previous_opcode_rules`, `core_vectors` |
| `M12` | `eval.rs` | Keep `0xf0` in `OP_SUCCESS` pre-scan when active | **Killed** | `activated_opcode_loses_early_success_bypass` (+7) |
| `M13` | `eval.rs` | Stack underflow check `< 3` instead of `< 4` | **Killed** | `three_item_stack_underflow_precedes_budget_exhaustion` |
| `M14` | `eval.rs` | Swap `a` and `b` arguments (`a * b == b * a`) | *Equivalent* | Mathematically identical function on validated equal-width `< m` inputs |
| `M15` | `eval.rs` | Swap `b` and `c` arguments (`a * c + b`) | **Killed** | `exact_budget_is_debited_and_missing_budget_fails` |
| `M16` | `eval.rs` | Budget off-by-one overdraft (`< -1` vs `< 0`) | **Killed** | `exact_budget_is_debited_and_missing_budget_fails` |
| `M17` | `eval.rs` | Pop 3 items instead of 4 (leave `a` on stack) | **Killed** | `exact_budget_is_debited_and_missing_budget_fails` |
| `M18` | `interpreter.rs` | Ignore `EXPERIMENTAL_MULADDMOD` in feature-off build | **Killed** | `unsupported_build_refuses_an_explicit_experimental_flag` |

---

## 7. Phase 6: Multi-Node Propagation, Reorganizations, and Soft-Fork Divergence

`scripts/research/campaign/reorg.py` orchestrated a **4-node live P2P network (`38 / 38` checks passed; `0` failures)** alongside an initial 3-node baseline (`33 / 33` checks passed):

- **Node `A`:** `bitcoin-rs-exp-fixed` (upgraded experimental regtest rules)
- **Node `B`:** `bitcoin-rs-exp-fixed` (independent upgraded peer)
- **Node `C`:** `Bitcoin Core v31.1.0` (unupgraded BIP 342 `OP_SUCCESS240` observer/miner)
- **Node `D`:** `bitcoin-rs-off-fixed` (unupgraded feature-off `bitcoin-rs` peer/miner)

### Verified Multi-Node Scenarios (`38 / 38` Passed)

1. **P2P Relay & Unupgraded Mempool Policy Isolation:**
   - Funding transaction and `OP_MULADDMOD` fraud-recovery transaction propagated cleanly over P2P from `A` -> `B` (`recovery_relays_A_to_B: true`).
   - Unupgraded `bitcoin-rs-off` node `D` and `Bitcoin Core` node `C` **rejected unconfirmed `0xf0` spends from their mempools** under `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS` (`unupgraded_bitcoin_rs_rejects_recovery_by_policy: true`), confirming that pre-activation mempools will not relay `0xf0` witnesses while accepting mined blocks from upgraded miners (`observers_follow_upgraded_chain: true`).
2. **Reorganization 1 (`recovery` -> `settlement` across 7-block fork):**
   - Partitioned `A` and `B`; `A` mined `recovery` at `funding + 1`; `B` mined `delay = 6` empty blocks plus `settlement` (`7` blocks total). Upon reconnection, `A` reorganized to `B`'s heavier chain (`depth = 7`), rolled back `recovery` UTXO, confirmed `settlement`, evicted the now-conflicting `recovery` from `A`'s mempool, rejected `recovery` re-submission (`bad-txns-inputs-missingorspent`), and converged to identical UTXO sets on `A` and `B`.
3. **Reorganization 2 (`settlement` -> `recovery` across heavier challenger chain):**
   - Partitioned again on a fresh funded claim; `A` mined `settlement` after `6` blocks while `B` mined `recovery` + `7` confirmations (`8` blocks total). Upon reconnection, `A` rolled back `settlement`, confirmed `recovery`, evicted `settlement` from mempool, and converged UTXO state across all nodes.
4. **Reorganization 3 (Funding-Block Reorg Resets Relative CSV Timer):**
   - `A` confirmed a funding tx at `h_1` and mined `6` blocks so `settlement` became BIP 68-final (`reorg3_settlement_mature_on_A: true`). `B` mined a heavier fork re-confirming the **same funding tx** `5` blocks higher (`h_2 = h_1 + 5`). After `A` reorganized onto `B`, the previously mature `settlement` transaction immediately became **consensus non-final again (`non-BIP68-final`)**, reopening the challenge window on `A` (`reorg3_csv_restarts_from_new_funding_height: true`, `reorg3_recovery_still_available: true`).
5. **Crash (`SIGKILL`) & Clean Restart Persistence:**
   - Performed abrupt stop/restart across both `A` and `B` after multiple reorganizations; verified exact chain tip, UTXO set, spent/unspent claim status, and post-restart P2P block/tx relay (`restart_A_preserves_*` and `restart_B_preserves_*` all `true`).
6. **Soft-Fork Divergence (Unupgraded Miner Mines False Arithmetic via `OP_SUCCESS240`):**
   - Submitted a false-arithmetic `0xf0` spend (`(7 * 11 + 3) mod 17` claimed unequal when actually equal) directly into a block mined by unupgraded `C`/`D` (`1cd2e823f39da6c4f08d19f87f5bb87c0e8d60f62a69c08b2ce91ff49d7321a3`).
   - **Upgraded nodes `A` and `B` rejected the block** (`upgraded_A_rejects_false_arithmetic_block: true`, `upgraded_B_rejects_false_arithmetic_block: true`) while unupgraded `C` and `D` accepted it under `OP_SUCCESS240`.
   - When upgraded `A` and `B` extended the valid chain by `2` blocks (including a valid `OP_MULADDMOD` spend), **both `C` (Bitcoin Core 31.1) and `D` (`bitcoin-rs-off`) cleanly reorganized onto the upgraded chain**, rolling back the false `OP_SUCCESS240` spend and converging all `4` nodes to a single tip (`C_reorgs_to_upgraded_chain: true`, `D_reorgs_to_upgraded_chain: true`). This empirically demonstrates standard soft-fork majority-hashrate convergence and minority-upgrade split risk.

---

## 8. Ranked Vulnerability and Risk Register

Findings are ranked by **Severity** and **Exploitability**, separating node implementation defects (fixed in this PR), pre-existing node performance/harness issues, and dispute-protocol architectural risks:

| ID | Category | Severity | Exploitability | Status | Component | Summary & Remediation |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| **`DEFECT-01`** | Node Consensus / Chainstate Integrity | **High** | Medium (RPC / local miner + reorg/invalidate) | **FIXED in PR** | `crates/chainstate/src/connect.rs`, `crates/node/src/mining.rs` | Re-submitting an invalidated block via `submitblock`, or locally mining within the same second after `invalidateblock` (`nonce = 0` hash collision), bypassed `DuplicateInvalid` and `NodeStatus::Invalid` header checks, re-connecting invalidated blocks onto `Chainstate` and poisoning active-chain descendants with `NodeStatus::Invalid`. Fixed + covered by 2 regression tests and `1,860`-sequence state-machine rerun (`0` violations). |
| **`PROTO-01`** | Dispute Protocol Completeness (`CE-02`) | **High** (if admission unverified) | High (malicious claim publisher) | Documented Protocol Boundary | Off-chain admission / Tapscript design (`muladdmod-dispute.md`) | Because `OP_MULADDMOD` aborts the transaction on non-canonical width/residue/modulus (`SCRIPT_ERR_MULADDMOD_ENCODING`), any funded claim whose `H(a), H(b), H(c)` commit to malformed bytes or non-minimal `<modulus>` makes the recovery leaf **permanently unspendable**, letting a dishonest operator settle after `delay`. **Mitigation:** Mandatory funder preimage inspection before funding, or add dedicated bit/length-dispute Taproot leaves / ZK admission proofs. |
| **`PROTO-02`** | Dispute Protocol Safety (`CE-01`) | **High** (if admission unverified) | Medium (dishonest challenger vs careless operator) | Documented Protocol Boundary | Off-chain admission (`muladdmod-dispute.md`) | If an operator commits `H(d)` to a non-canonical encoding (`d >= m` or padded width) of an integer-correct residue, `OP_MULADDMOD` outputs canonical `r < m` and byte-wise `OP_EQUAL OP_NOT` evaluates `true`, confiscating an honest claim. **Mitigation:** Operator and funder must enforce `len(d) == len(m)` and `d < m` before signing/funding. |
| **`PROTO-03`** | Dispute Protocol Authentication (`CE-03`) | **High** (if P2TR key unverified) | High (malicious claim publisher) | Documented Protocol Boundary | Off-chain P2TR verification | Inspecting leaf assembly without recomputing tweaked output key `Q` from `NUMS_X` and single-leaf `merkle_root` allows immediate key-path theft or hidden backdoor sibling leaves. **Mitigation:** Reconstruct exact `v1` witness program bytes before funding. |
| **`PERF-01`** | Pre-existing Tapscript CPU DoS Amplification | **Medium** | Medium (1-input 4M-WU block with large annex + many `CHECKSIG`s) | Open (Pre-existing on `dev`) | `crates/script` Taproot sighash | Single-input Tapscript with `76,685` `OP_CHECKSIGVERIFY` ops and a `3.85 MB` BIP 341 annex takes **`402.8s`** (`~295 GB` SHA-256) because `sha_annex` is recomputed per signature check instead of cached per input (`OP_MULADDMOD` itself takes `4.94s` and is unaffected). **Recommendation:** Precompute `PrecomputedTxData` + per-input `sha_annex` once per transaction/input in `crates/script`. |
| **`OPER-01`** | Dispute Liveness (`CE-05`, `CE-06`) | **Medium** | Medium (fee spike, full-RBF race, or deep reorg) | Architectural / Parameterization | Mempool RBF & CSV `delay` | Full-RBF allows higher-fee operator settlement to evict unconfirmed recovery once `height >= funding + delay - 1`; `delay = 1` leaves `0` exclusive challenge blocks; a `>= delay`-block reorg reverses confirmed recovery. **Mitigation:** Set `delay >= D_reorg + D_censorship` (`>= 144..1,008` blocks on mainnet), pre-fund CPFP/P2A anchors, and broadcast recovery immediately. |
| **`DEFECT-03`** | Native Memory Safety (`libzmq` Over-Aligned Store `SIGSEGV`) | **Medium-High** | Deterministic crash whenever `malloc` chunk is `< 32 B` aligned | **FIXED in PR** | `.cargo/config.toml` (`zeromq-src 0.2.6+4.3.4`) | Vendored `libzmq` declares `struct alignas(ZMQ_CACHELINE_SIZE) command_t` (`64 B`), causing GCC on `x86_64-unknown-linux-gnu` to emit aligned AVX `vmovdqa` stores in `ypipe_t<command_t, 16>::write` during `ctx_t::terminate`, while `zeromq-src` built `yqueue.hpp` without `HAVE_POSIX_MEMALIGN` (16-byte `malloc`), crashing `zmq_publisher_handle_reports_active_metadata` with `SIGSEGV` in CI. Fixed by setting `-DHAVE_POSIX_MEMALIGN=1 -DZMQ_CACHELINE_SIZE=64` for `x86_64-unknown-linux-gnu` and adding a 16-iteration ZMQ teardown stress step. |
| **`PROTO-04`** | Challenger Centralization & Sighash (`CE-04`) | **Medium** | Low-Medium (`recovery_secret` compromise or liveness loss) | Documented Protocol Boundary | Recovery leaf (`<recovery_pk> CHECKSIGVERIFY`) | Recovery requires a single `recovery_secret` (preventing permissionless watchtowers) and imposes no output covenant (`SIGHASH_NONE` redirects funds). **Mitigation:** Use covenant/presigned recovery outputs + ephemeral P2A fee-bump anchors so any watchtower with `(a, b, c, d)` can trigger slash/burn/reimbursement. |
| **`DEFECT-02`** | CI Workflow Coverage | **Low** | N/A | **FIXED in PR** | `.github/workflows/muladdmod-research.yml` | Push trigger specified `'feat/experimental-muladdaddmod'` (typo) instead of `'feat/experimental-muladdmod'`, and shared push/PR concurrency cancelled push runs. Fixed trigger, event-scoped concurrency, experimental Clippy gate, and Python test discovery. |
| **`DEFECT-04`** | CI Workflow YAML Syntax | **Low** | N/A | **FIXED in PR** | `.github/workflows/main.yml` | Unquoted YAML scalar containing `:: ` on line 262 (`kernel_block_parity:: ...`) caused GitHub Actions YAML parser failure on branch pushes. Converted to a block scalar; also updated 3 pre-existing constructs for Rust `1.100.0` Clippy compatibility. |
| **`HARNESS-01`** | Test Harness Reliability | **Low** | Local interactive TTY runs | Documented (Pre-existing on `dev`) | `scripts/run-p2p-core-interop.sh` | When `${CORE_COOKIE_FILE}` is absent during `cleanup()`, `core_rpc stop || true` runs `curl --user ""`, prompting `/dev/tty` for a password and hanging interactive test runs (`< /dev/null` avoids it). |
| **`DEP-01`** | Transitive Optional Crate Advisory | **Informational** | None on `fjall` builds | Tracked (`RUSTSEC-2026-0418`) | `Cargo.lock` (`libz-sys 1.1.30`) | Build-script `CFLAGS` cross-target env leak in optional `rocksdb` transitive dependency; not compiled or linked in `fjall` native binaries. |

---

## 9. Current BitVM3 Assumptions vs `OP_MULADDMOD` Guarantees

### 9.1 Architectural Comparison Matrix

| Dimension | Current BitVM3 (Garbled Circuits / Limb Emulation on Today's Bitcoin) | `feat/experimental-muladdmod` + Funded Dispute Fixture | Remaining Gap for Production Transparent BitVM3 Verifier |
| :--- | :--- | :--- | :--- |
| **256-bit Modular `(a * b + c) mod m` Cost in Script** | Tens of thousands of opcodes (`OP_ADD`/`OP_SUB` 31-bit limb decomposition, lookup tables, or multi-megabyte garbled labels across many Tapleaves) | **Single opcode (`1 B`), `50` budget units, `294 B` complete authenticated dispute leaf** (including SHA-256 preimage checks, CSV, and Schnorr keys) | Optimize host/node `muladdmod.rs` from byte-loop (`87 us`) to `[u64; 4]` limbs (`< 4 us`); evaluate companion primitives (`OP_CAT` or Merkle-path verification) for trace compression. |
| **Offline Garbling / Trusted Setup / Presigning** | Requires massive offline garbled-circuit generation (`GB..TB` ciphertext commitments), operator-verifier presigned transaction graphs, and `1-of-N` honest committee key-erasure assumptions | **Zero garbling and zero committee key-erasure for the arithmetic step itself** -- native consensus directly checks `(a * b + c) mod m != d` in clear witness bytes | Multi-step bridge payout covenants and slash routing still require either presigned transaction DAGs or a covenant opcode (`OP_CTV` / `OP_TXHASH` / `OP_CAT` + CSFS) on Bitcoin. |
| **Modulus Flexibility** | Custom limb circuits per prime (`BN254`, `BabyJubjub`, `Goldilocks`, `M31`, `Secp256k1`, `Curve25519`); composite moduli very expensive | **Arbitrary runtime or script-pinned modulus `2 <= m <= 2^256 - 1`** (`1..32` bytes, prime or composite) with uniform semantics | Compiler front-end must pin `<modulus>` as a canonical minimal-LE constant per circuit gate type. |
| **Step Connectivity (Trace Soundness)** | Bit commitments (Lamport / Winternitz / garbled wire labels) bind output wire of gate `i` to input wire of gate `i + 1` | **Isolated single-step claim (`H(a), H(b), H(c), H(d)`)** -- does **not** prove `a_i` equals `d_{j}` from an earlier gate unless `H(a_i) == H(d_j)` is verified off-chain or via bisection | **Trace commitment & bisection compiler:** bind wire values across `2^N` trace steps via shared SHA-256 digests (`H(wire_k)`) or interactive bisection narrowing to one inconsistent `(H(a), H(b), H(c), H(d))` gate. |
| **Malformed Witness / Non-Canonical Preimage Handling** | Bit/limb encodings can either be range-checked in Script or rejected by bit-commitment structure | **Aborts transaction (`SCRIPT_ERR_MULADDMOD_ENCODING`)** -- cannot slash malformed operator preimages inside the `OP_MULADDMOD` leaf (`CE-02`) | **Encoding-fault slash leaves:** add companion Tapleaves proving `SIZE(x) != w` (`OP_SIZE <w> OP_NUMNOTEQUAL`) or byte-wise lexicographic `x >= m` so malformed operator revelations are slashable on-chain. |
| **Watchtower Permissionlessness & Fee Pinning** | Vulnerable to fee-pinning/RBF unless paired with TRUC (v3) + Pay-to-Anchor (`P2A`) ephemeral outputs and covenant-locked slash destinations | Requires `recovery_secret` signature (`CE-04`) and uses v2 full-RBF-replaceable transactions (`CE-05`) | **Permissionless fraud leaf + TRUC/P2A:** lock recovery payout via covenant/presigned template and fund challenge fees via child `P2A` CPFP so any watchtower holding `(a, b, c, d)` can confirm recovery without a hot key. |
| **Consensus Deployment Readiness** | Active on mainnet today (no soft fork required, at extreme off-chain/witness cost) | Private `0xf0` regtest experiment; `VerifyFlags::EXPERIMENTAL_MULADDMOD` gated to regtest (`height >= taproot`) | Assign formal BIP number, opcode byte, BIP 9 / speedy-trial signaling parameters, and cross-implementation differential vectors (`Bitcoin Core` + `bitcoin-rs`). |

### 9.2 Concrete Conditions Before Production BitVM3 Integration

To build a production-grade transparent BitVM3 fraud-proof compiler on top of `OP_MULADDMOD`, seven concrete conditions remain:

1. **On-Chain Encoding-Challenge Leaves (Eliminating `PROTO-01` / `CE-02`):** Whenever operand hashes `H(a), H(b), H(c), H(d)` are revealed dynamically during an interactive challenge game (rather than inspected in clear before funding), the Taproot tree **must** include dedicated slash leaves for:
   - **Width fault:** reveal `x` matching `H(x)` with `OP_SIZE <w> OP_EQUAL OP_NOT` (trivially `8` bytes of existing Script!).
   - **Range fault (`x >= m`):** reveal `x` matching `H(x)` and verify `x >= m` via `w` byte-slicing steps (or nibble/bit commitments) without invoking `OP_MULADDMOD` (since `OP_MULADDMOD` aborts on `x >= m`).
2. **Canonical Output Enforcement (`PROTO-02` / `CE-01`):** Prover/operator software must deterministically serialize claimed wire `d` as fixed `w`-byte little-endian in `[0, m - 1]`; committing non-canonical bytes makes honest claims slashable.
3. **Wire-Equivalence / Bisection Trace Compiler:** Compile R1CS / Plonk / AIR verifier arithmetic (`F_p` inner products, FRI folding, Fiat-Shamir state transitions) into fixed-width `OP_MULADDMOD` gates where shared wire hashes `H(w_k)` link producer gate output `d` to consumer gate input `a`/`b`/`c`, paired with logarithmic bisection over state roots.
4. **Permissionless Watchtowers + Covenant / Presigned Slash Outputs + TRUC (`v3`) / `P2A`:** Remove `<recovery_pk> OP_CHECKSIGVERIFY` from the fraud leaf once payout destination is bound (via presigned connector/covenant), and adopt `version = 3` (BIP 431 TRUC) + Pay-to-Anchor (`P2A`) outputs to prevent third-party package pinning and RBF fee griefing (`OPER-01`).
5. **Conservative Challenge Horizon:** Set `delay >= D_reorg_max + D_fee_congestion` (for mainnet bridges, typically `>= 1,008` blocks / ~1 week, never small test constants like `1..6`).
6. **Limb-Arithmetic Fast Path & Cached Annex Sighash (`PERF-01`):** Replace the `33`-byte bit-by-bit loop in `crates/script/src/muladdmod.rs` with `[u64; 4]`/`[u64; 8]` limb multiplication + Knuth D reduction, and cache `sha_annex` per input in `crates/script` Taproot sighash evaluation.
7. **Formal Soft-Fork Specification:** Draft BIP specification covering exact opcode assignment, activation signaling (never unconditional regtest burial on public networks), and reference test vectors shared with Bitcoin Core.

---

## 10. Epistemic Matrix: Verified Properties, Conditional Assumptions, and Untested Areas

Per campaign methodology, **failure to discover a consensus arithmetic exploit is inconclusive outside the tested input and state space**. The table below delineates exact epistemic boundaries:

| Category | Scope & Basis |
| :--- | :--- |
| **Passing Empirical Tests** | - `12,037` valid + `293` malformed Spiral v0.2 vectors (`0` mismatches).<br>- `25,300` randomized differential script evaluations (`0` mismatches vs Python `refinterp.py`, `0` soft-fork violations, `0` feature-off leaks).<br>- `1,508` Bitcoin Core static script/tx vectors + `50` live 3-way cases against `Bitcoin Core v31.1.0` (`0` divergences).<br>- `4 x 4,096` `proptest` algebraic/encoding/dispute cases (`103/103` Rust script tests).<br>- `164` live Phase 2 adversarial dispute transactions (`158/158` `refinterp.py` parity).<br>- `1,860` post-fix bounded state-machine sequences (`7,960` RPC steps, `0` violations).<br>- `18` source mutants (`17/17` non-equivalent killed).<br>- `38/38` 4-node P2P propagation, reorganization, crash/restart, and soft-fork split checks.<br>- `10` full-block (~4M WU) `submitblock` benchmarks + `64` width `1..=32` microbenchmark classes. |
| **Verified Security Properties** | - **Bounded memory & termination of `eval_muladdmod`:** Fixed `[u8; 33]` stack buffers, zero heap allocation inside arithmetic core, bounded loop counts (`<= 32 * 8 = 256` iterations), no panics or integer overflows.<br>- **Strict Tapscript + flag + Cargo-feature isolation:** Legacy, SegWit v0, key-path Taproot, non-`0xf0` `OP_SUCCESSx`, and feature-off builds preserve exact pre-fork semantics; mainnet/testnet/signet have no code path setting `VerifyFlags::EXPERIMENTAL_MULADDMOD`.<br>- **Invalidated-block persistence (`DEFECT-01` fix):** `NodeStatus::Invalid` blocks and children of `NodeStatus::Invalid` headers cannot reconnect via `submitblock`, P2P, or local mining.<br>- **Conditional Dispute Safety, Completeness, Exclusivity, and Replay Isolation:** Verified over canonical admitted claims under `CA-1..CA-3`. |
| **Conditional Assumptions** | - Standard cryptographic hardness of SHA-256 (`CA-1`), BIP 340 Schnorr (`CA-2`), and BIP 341 NUMS discrete log (`CA-3`).<br>- Off-chain funder admission (`AP-1`) validating canonical operand/modulus widths and reconstructing the exact single-leaf `NUMS_X` P2TR output key.<br>- Challenger key availability (`recovery_secret`), `SIGHASH_DEFAULT`/`SIGHASH_ALL` signing discipline, fee-bump liquidity, and adversarial reorg depth `< delay`. |
| **Untested / Out-of-Scope Areas** | - **Formal machine-checked theorem proving (Lean/Coq/Kani)** of the Rust bytecode interpreter (`eval.rs` + `muladdmod.rs`): `muladdmod.rs` was tested via exhaustive boundary vectors, `4,096`-case `proptest` against Knuth D limbs, and `18` mutants, not formally proved with SMT/bounded model checking across all $2^{1024}$ `(a, b, c, m)` 256-bit tuples.<br>- **Multi-step BitVM3 interactive bisection DAGs, connector trees, and TRUC/P2A package relay:** Only single-step funded arithmetic claims were implemented and tested in this repository.<br>- **ARM64 / 32-bit / non-Linux hardware benchmarks:** Cost measurements were collected on x86_64 Zen 5 (`AMD Ryzen AI 9 365`) under Linux/WSL2; slower ARM SBC verification hardware (e.g., Raspberry Pi 4/5) will exhibit proportionally higher absolute block times (`~3x-5x` wall time, maintaining the same `~3x` ratio in favor of `OP_MULADDMOD` vs `OP_CHECKSIGVERIFY`).<br>- **BIP 9 / speedy-trial state-machine transitions:** Activation on regtest uses height-gated Taproot burial (`experimental-muladdmod-regtest`), not version-bits signaling. |

---

## 11. Synchronization Contract Impact (`AGENTS.md`)

This campaign modified two authoritative production files to fix `DEFECT-01`:

- `crates/chainstate/src/connect.rs`: `validate_contextual_block_header` rejects headers marked `NodeStatus::Invalid` or building on a `NodeStatus::Invalid` parent (`ValidationError::KnownInvalidHeader`).
- `crates/node/src/mining.rs`: `MiningCoordinator::submit` returns `SubmitOutcome::DuplicateInvalid` for `NodeStatus::Invalid` blocks before `Chainstate::contains_block`, and `MiningCoordinator::generate_one` skips candidate nonces colliding with existing `HeaderIndex` entries.

**Affected contracts (`docs/architecture/synchronization-contracts.md`):**

- **`SYNC-04` (Invalid Block Rejection & Valid-Prefix Preservation, Safety):** Strengthened. Prevents previously invalidated blocks or descendants of invalidated headers from re-entering `Chainstate` or poisoning active-chain `NodeStatus` metadata.
- **`SYNC-06` (Chain Reorganization & Tip Convergence, Safety/Liveness):** Strengthened. Ensures `invalidateblock` + subsequent local mining or `submitblock` maintains consistent `HeaderIndex` and `Chainstate` tip invariants.
- **`SYNC-03` (Notification Non-Authority, Safety):** Unchanged. `.cargo/config.toml` (`DEFECT-03`) repairs memory alignment in the optional `libzmq` publisher allocator on `x86_64-unknown-linux-gnu` so `SocketZmqPublisher` teardown cannot `SIGSEGV`, without changing notification semantics or granting ZMQ chainstate authority.
- **Proof obligations:** `crates/chainstate/src/connect/tests.rs::invalidated_header_and_invalid_parent_cannot_validate_or_commit`, `crates/node/tests/mining/submission.rs::submit_and_generate_refuse_invalidated_blocks_and_mine_distinct_replacements`, `crates/node` `zmq_publisher_handle_reports_active_metadata`, `crates/chainstate` `invalid_middle_block_keeps_valid_prefix`, and `cargo run -p contract-index -- --check` (verified green).

---

## 12. Reproducing the Campaign

All adversarial harnesses, reference interpreters, differential fuzzers, benchmarks, state-machine explorers, and mutation runners are committed in-tree with zero external Python dependencies (`Python 3.10+` standard library only):

```sh
# 1. Build experimental and feature-off release binaries + script oracle + microbenchmark
cargo build --locked --release -p bitcoin-rs --no-default-features \
  --features fjall,experimental-muladdmod-regtest
cp target/release/bitcoin-rs /tmp/bitcoin-rs-exp
cargo build --locked --release -p bitcoin-rs --no-default-features --features fjall
cp target/release/bitcoin-rs /tmp/bitcoin-rs-off
cargo build --locked --release -p bitcoin-rs-script --examples --features experimental-muladdmod

# 2. Run Rust unit, Core vector differential, and 4,096-case property suites
PROPTEST_CASES=4096 cargo test --locked -p bitcoin-rs-script --features experimental-muladdmod
cargo test --locked -p bitcoin-rs-chainstate invalidated_header_and_invalid_parent
cargo test --locked -p bitcoin-rs-node --no-default-features \
  --features fjall,experimental-muladdmod-regtest submit_and_generate_refuse_invalidated

# 3. Run Python offline unit suites (claim vectors + campaign reference interpreter)
python3 -m unittest discover -s scripts/tests -p 'test_muladdmod*.py' -v

# 4. Phase 1: Live small-field (m=17) and wide-field (m=2^255-19) dispute fixtures
python3 scripts/research/muladdmod_dispute_rpc.py /tmp/bitcoin-rs-exp --report /tmp/dispute-small.json
python3 scripts/research/muladdmod_dispute_rpc.py /tmp/bitcoin-rs-exp --wide --report /tmp/dispute-wide.json

# 5. Phase 2: 164-case adversarial dispute-contract campaign
python3 -m scripts.research.campaign.attacks /tmp/bitcoin-rs-exp --report /tmp/phase2-attacks.json

# 6. Phase 3: Randomized consensus differential + live 3-way Bitcoin Core differential
python3 -m scripts.research.campaign.differential target/release/examples/script_oracle \
  --cases 10000 --seed 7 --report /tmp/phase3-diff.json
python3 -m scripts.research.campaign.core_diff /tmp/bitcoin-rs-exp /tmp/bitcoin-rs-off \
  "$(command -v bitcoind)" --report /tmp/phase3-core.json

# 7. Phase 4: Width 1..32 microbenchmarks + ~4M-WU full-block validation benchmarks
./target/release/examples/muladdmod_cost --ops 2000 --reps 15 > /tmp/phase4-microbench.json
python3 -m scripts.research.campaign.blockbench /tmp/bitcoin-rs-exp --report /tmp/phase4-blockbench.json

# 8. Phase 5: 1,860-sequence bounded state machine + 18-mutant source campaign
python3 -m scripts.research.campaign.statemachine /tmp/bitcoin-rs-exp --report /tmp/phase5-sm.json
python3 -m scripts.research.campaign.mutation --report /tmp/phase5-mutation.json

# 9. Phase 6: 4-node propagation, deadline reorgs, crash/restart, and soft-fork split
python3 -m scripts.research.campaign.reorg /tmp/bitcoin-rs-exp \
  --unupgraded-rs-binary /tmp/bitcoin-rs-off \
  --core-binary "$(command -v bitcoind)" \
  --report /tmp/phase6-reorg.json
```
