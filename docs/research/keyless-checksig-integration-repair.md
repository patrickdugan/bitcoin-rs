# Keyless integration repair and validation

The tested runtime source is `f90037ec1ba8ab8678097f33aaebc89471282830`. This commit follows the original
`e616005407071dc1241bd17f891522f663cb1b34` integration and the independent
[audit and shutdown-helper repair](keyless-checksig-local-audit.md).
This work uses Keyless CHECKSIG / TXCOMMIT, separate from OP_MULADDMOD.

## Implemented checkpoint repair

WSL's Windows mount accepted directory sync but rejected
`renameat2(RENAME_NOREPLACE)` with `EINVAL`. Both existing publication tests
failed before the repair on that mount. They passed after the repair.

Publication now uses the existing portable protocol on every platform.
Exclusive directory creation reserves a generation. Artifact files, the
manifest, the generation directory, and its parent are synced before the
atomic `CURRENT` replacement. Recovery ignores unreferenced generations.
The historical durable-head reference keeps its existing ordering and retention.
Existing generations and temporary `CURRENT` names are never overwritten.
The stored format stays at the current schema epoch. Real I/O failures remain errors.

The removed rename has no failure boundary after this change. Its test-only
failpoint was removed with it. All remaining write, sync, and publication
failpoints retain their checks. The confined no-replace helper and its own
escape/collision tests remain unchanged for other callers.

## Actual follow-up results

| Check | Result |
| --- | --- |
| Existing Windows-mount publication tests before fix | 0 passed, 2 failed with OS error 22 |
| Same tests after fix, with fault injection | 2 passed |
| Native checkpoint owner suite | 17 passed, 0 failed or ignored |
| Offline Python staging | 35 passed |
| Final full node `fjall,zmq` profile | 384 passed, 2 existing skips, no retries |
| Unchanged isolated shutdown suite | 3 passed; original six-second deadlines retained |
| Funded fixture on Windows mount | 29 rejections, two payouts, exits `[0, 0]` |
| Native adversarial campaign | 36 block rejections, 12 positives, 7 confirmed, exits `[0, 0]` |
| Additional Windows-mount persistence | Three reopens, four verified generations; exits `[0, 0, 0, 0]` |
| Formatting and whitespace | Passed |

One earlier repaired full node run recorded 382 passes and two six-second
startup/shutdown deadline failures while the independent stress campaigns
overlapped. Its failed receipt and logs remain in `node-profile-after`.
The same three shutdown tests then passed in isolation with no source or
deadline changes. After the stress ended, the complete final profile passed
with two concurrent tests. The failed run is not counted as a pass.
The two existing skips are subprocess entrypoints that the owning contender
and SIGKILL tests invoke explicitly.

The initial pinned audit separately reproduced 34 Python tests and 511 Rust
executions across the Keyless/CAT feature matrix at `e6160054`. Those are
baseline results, not a second full feature-matrix run at the repaired source.

### Binary, host, and network identity

The repaired Linux x86-64 executable reports `bitcoin-rs daemon version 0.15.0`.
Its SHA256 is `3899986f81d8da1f7977d5d9ebe3fe27df617971ce8ae6552e80a479e5a84d3b`.
The preserved artifact is `../evidence/fixes/artifacts/bitcoin-rs-f90037ec1`
relative to the local checkout. The clean-source build receipt is
`../evidence/fixes/build-after/report.json`.

The native test tools were Rust/Cargo 1.99.1, Python 3.12.3, Git 2.43.0, and
cargo-nextest 0.9.148. The host was Ubuntu 24.04 on WSL2, kernel 6.18.54.1,
glibc 2.39. No new software was installed.

The runtime experiments ran only on isolated patched regtest with zero public
peers. Its RPC genesis was `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206`.
The separately verified genuine public Testnet4 fixtures retain genesis
`00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043`.
Their existing header, PoW, transaction, merkle and witness checks, stock Core
replay and integrity-tamper controls remain in the initial audit packet.
The generic annex tests use that verified public block hash as data.
Public Testnet4 does not activate TXCOMMIT or this CAT experiment, and no
experimental output or spend was broadcast there.

### Positive and negative receipts

The Windows-mount fixture funded three 100,000-sat reserves at height 102.
Two 98,000-sat payouts confirmed at height 103, each with a 2,000-sat fee.
The policy remains 191 bytes, with the anchored 138-byte prefix and 42-byte
suffix. Its funding transaction was `0b27cd4d517a6442979caf49a4a9cda8910aa8106755fcb0617019c8d7367037`.

| Recipient | Payout transaction | Sats |
| --- | --- | ---: |
| 0 | `2badefb8f161e423cd4c4736bd3324e3f89bd80704114863d2928395ee6a1ffc` | 98000 |
| 1 | `e7ea52a32795e2dc6db2364645b6d7e5a5c1a4e75c44d0ea225651c85698f447` | 98000 |

The adversarial receipt checks transaction layout and annex mutations, failed
check abort versus inversion, all three signature opcodes, signature budget,
recipient/amount binding, and spent-input replay before and after restart.
Each rejected block preserves height. Raw transactions, positive blocks,
errors and node logs are retained in `adversarial-after/patched`.

The separate Windows-mount process test advanced three blocks across clean
shutdowns and reopened each resulting tip. A final reopen confirmed height 3.
All four shutdowns exited zero. Each selected manifest and every header, UTXO
and CoinStats artifact length and SHA256 were verified.

| Height | Checkpoint generation | Verified block hash |
| ---: | ---: | --- |
| 1 | 1 | `5f106bf7ce959140de0600a798f6e80f359b9e77d65125275a25d0d81d2946d8` |
| 2 | 2 | `209b3eddbadb61650e94d13dd4aa7f387a8552d6120541d855aa0192cf153e1f` |
| 3 | 3 | `5ad4f00fd4c2c7aa71a3b3915d7cbf23b43cbac44c54a3f5be12542d55d2f0a9` |
| 3 | 4 | `5ad4f00fd4c2c7aa71a3b3915d7cbf23b43cbac44c54a3f5be12542d55d2f0a9` |

## ZMQ finding remains unlocalized

The [original broad CI run](https://github.com/patrickdugan/bitcoin-rs/actions/runs/43249495342)
recorded SIGSEGV in
`zmq_publisher_handle_reports_active_metadata`. Its cause is not proven to be
inherited or fixed. This change contains no speculative ZMQ runtime edit.

The original test passed 100 nextest repetitions, 1,000 trials from an immutable
test binary with four bounded child processes, and 40 heap-perturbed trials.
The original complete node profile also passed all 384 tests. The repaired
profile's ZMQ check passed. A separate probe using the same vendored libzmq
4.3.4 passed 2,000 two-socket context lifecycles. No local SIGSEGV was observed.
The frozen test binary SHA256 is `0b4c0645f90d79b9e200e0cd4c12dcf8aedb00b094cf7bd7b952eb237a4244f6`.

The failing CI host used Ubuntu 26.04.1, nextest 0.9.143 and mold
2.40.4+dfsg-2.1ubuntu1. Those differ from the installed local environment.
A failing backtrace or reproduction in that environment is still needed to
claim a causal ZMQ repair. Green staging or a later green CI run cannot prove
the old intermittent fault is eliminated.

## Reproduce and inspect

Use a clean checkout and fresh output directories. Keep the node binary and
source identities together. The recorded build command was:

```sh
cargo build --locked --jobs 2 --profile quickstart -p bitcoin-rs \
  --no-default-features \
  --features fjall,experimental-keyless-checksig-regtest,experimental-op-cat-regtest
cargo test --locked --jobs 2 -p bitcoin-rs-storage --lib checkpoint::
cargo nextest run --locked --build-jobs 2 --test-threads 2 \
  --no-fail-fast --retries 0 -p bitcoin-rs-node \
  --no-default-features --features fjall,zmq
```

Set `TMPDIR` to an existing fresh directory on `/mnt/c` and select
`checkpoint::tests::publication_` to reproduce the affected filesystem checks.
Run the documented `regtest` staging profile with the recorded binary SHA256
and source revision. For the mounted-node fixture, pass that `TMPDIR` to the
staging process. The additional adversarial tool uses isolated native data.
The local `../evidence/fixes` packet retains actual commands, source diffs,
exit status, time bounds, logs and digests, including every failed attempt.

| Receipt or log | SHA256 |
| --- | --- |
| `checkpoint-before/command.log` | `21d1784ff65e967c5746db89d66f4bc77f61ea09f4e7b799c836c2b23a75ffd8` |
| `checkpoint-after/command.log` | `47e39be15d8738c9d4b4ff5588e09f2bcb0dab6d9b041898c863ea910866ec9e` |
| `checkpoint-native-after/command.log` | `ee9934cb66b6d012b945be35f6030ce1206c46b9f79f85ba5015e3782be23aa1` |
| `node-profile-final/command.log` | `92bcd77bcce16ac2d2bffa28e8e21487c87d43c8668d1b80da8162373c5f7389` |
| `mounted-staging-after/keyless-regtest.json` | `262e5116239f2fa2b2b168a0658b9409aac1946d8ea5f66919486d01e3b92779` |
| `adversarial-after/patched/report.json` | `3e8723c9b425885b45cdf574fa1a5535aeb25cc3afef3ddeaf071e1d1ca25d4f` |
| `mounted-persistence-after/report.json` | `bb9f3ab20d4a5b288928ecd191b8f0ab826d2205e311662120d6185322eecc3a` |
| `zmq-frozen-stress-before/report.json` | `5a89cdcada5b269bb7e6377b50fb91c1d968000672d64232b41769c405f1f09e` |

## Synchronization and research scope

The original proposal changes native input validation and next-block admission
flags only when its regtest experiments are selected. The checkpoint repair
touches the persistence/publication path used at shutdown and recovery.
It can affect `SYNC-04` failure classification and `SYNC-05` durability before
publication. Checkpoint ownership remains in storage; chainstate keeps the
authoritative durable head. The final node profile runs the mapped
`crash_recovery` matrix, including SIGKILL/reopen and checkpoint-gap recovery.
The owner tests preserve the previous `CURRENT` across injected failures.
No optional RPC/ZMQ owner acquires chainstate authority (`SYNC-03`).

NUMS P2TR is not P2MR. These results establish no general computation-proof
application binding, BIP allocation/activation or production cost calibration.
No mainnet wallet or real funds were used. No merge was performed.
