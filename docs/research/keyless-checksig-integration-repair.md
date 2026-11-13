# Keyless integration repair and validation

The checkpoint repair was first tested at
`f90037ec1ba8ab8678097f33aaebc89471282830`.
The final tested code is `13d3179e656a9f23b8da66625d4e16f3c064bca1`. Its runtime and exact current-toolchain gate are recorded below. The checkpoint repair follows the original
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
glibc 2.39. That initial validation installed no new software; the approved
isolated compiler follow-up is recorded below.

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

## Rust 1.100 CI compatibility follow-up

The preceding CLTV follow-up tested code `4e64c2b49828f77cd0a78efa5ba581a1ad5fe2f5`.
The first pushed head, `1628b050a0bd54840a6908fe4d38593f5e7777c0`, encountered
a new Rust 1.100 Clippy `needless_bool` diagnostic in the existing CLTV checker.
The final-sequence guard now directly returns
`input.sequence.to_consensus() != SEQUENCE_FINAL`.
This is the same unsigned-integer predicate as the old false/true branch.
No locktime condition, feature flag, test assertion or lint level changed.

The complete script suite with both companions passed 95 tests, including its
independent BIP65 table and Core vectors. All script targets also passed the
installed Rust 1.99.1 Clippy with warnings denied. The clean-source executable
was rebuilt with the original explicit regtest features. It is byte-for-byte
identical to the earlier checkpoint-repair binary:
`3899986f81d8da1f7977d5d9ebe3fe27df617971ce8ae6552e80a479e5a84d3b`.
The final source and build receipt are in `build-ci-followup/report.json`.
Its preserved artifact is `artifacts/bitcoin-rs-4e64c2b49` in the
follow-up evidence packet.

The final artifact passed the mounted funded fixture again: two 98,000-sat
payouts, all 29 negatives, restart preservation and exits `[0, 0]`.
It also passed the native campaign again: 36 block rejections, 12 positives,
seven confirmations, spent-input replay refusal and exits `[0, 0]`.
These fresh receipts are under `ci-followup`.

The [intermediate Keyless workflow](https://github.com/patrickdugan/bitcoin-rs/actions/runs/43321380405)
passed both jobs with Rust 1.100. Its test ZIP was downloaded and matched
GitHub's archive SHA256. Every recorded test-log digest and executed-test
summary was checked: 35 Python tests and 511 Rust executions, zero failed or
ignored. The CI source was the clean test merge
`7bd4872cf2e296fa0494a315e90a61c71ca1a5e9`. Its tree
`9f7365ec59755e605f7ef88be756eb078232d7ef` exactly matches `1628b050a`.
The broader intermediate CI run stopped at Clippy before `test-crates` ran.
The latest-head status is reported separately on the PR checks page.

The original 112-file evidence packet was rechecked after this work:
198,768,440 bytes, zero digest mismatches. The old receipts remain intact.

| Follow-up receipt or log | SHA256 |
| --- | --- |
| `build-ci-followup/command.log` | `013e1746dccd87b2124a584090d22e73af291233fb9204559b7fcdb5c73ee24b` |
| `cltv-script-after/command.log` | `9d2ba95c7efb84c37c2a6bcfe6738339e788a3b906a1027eaa5a544cd855c5a0` |
| `cltv-clippy-after/command.log` | `c93ace729ae9949fca6c37776909218821853fab87c265b2c5280a551b3f41c6` |
| `ci-followup/mounted-staging/keyless-regtest.json` | `dc5539eee2d78242b700dd04fd9afe5ce9a2fd40acbb8fb9fbb9003132975712` |
| `ci-followup/adversarial/patched/report.json` | `cd8b1de4f877048cd17751e3cf8d6f2c14a2cb5259e5423011c5ca45281dad9f` |
| `ci-1628-tests/artifact.zip` | `151a4aae48023c4296b66b19cefda0b763aabb7d334a08ef68e4bb91e63c5686` |

## Final current-toolchain gate and runtime

The final tested code is `13d3179e656a9f23b8da66625d4e16f3c064bca1`. Rust 1.100 also reported an existing
fee-estimator range-loop lint and an address-manager boolean-guard lint.
The estimator now iterates over the same fixed-array suffix with `iter_mut`
and `skip`; offsets at or beyond the array length still update no entries.
The address manager returns the equivalent `!final_pending && eligible`
predicate. The self-address refusal and short-circuit order remain intact.
No estimator schema, peer-selection rule, validation rule or activation flag
changed. No lint level or test assertion was relaxed.

An approved tool invocation installed official Rust 1.100.0 and Clippy in
task-only `/tmp/keyless-rustup-19b-1100`, with a separate temporary Cargo home.
The installer used the minimal profile and disabled self-update. The normal
MSI compiler was checked afterwards and remains Rust 1.99.1. The new compiler
was used explicitly for the exact `scripts/ci-pr.sh clippy` lane.
A preliminary warnings-only collection was recorded as diagnostics, not as
a passing gate. On the final formatted source, all four strict profiles and
the production silent-payments check passed with warnings denied, jobs 2.

The existing estimator suite passed 17 tests. The address-manager owner and
Core fixture suite passed 83 tests. Neither suite failed or ignored a case.
Their captured patch SHA256 matches the committed final code exactly.
The earlier CLTV follow-up's 95 script tests remain separate evidence.

A clean-source final executable was rebuilt with the unchanged explicit
regtest-only features. Its version is 0.15.0, SHA256
`b0b67335ea4aca2243c5b550d60aa8435513b47a620a8de3be9f7505c8ffbaea`. The artifact is
`artifacts/bitcoin-rs-13d3179e6` in `../evidence/fixes`.
The build and fresh replay receipts are `build-final/report.json` and
`final-runtime/report.json`.

The final executable passed the Windows-mount fixture again: two confirmed
98,000-sat payouts, all 29 negative cases, restart and exits `[0, 0]`.
The native adversarial campaign again passed 36 block rejections, 12 positive
cases, seven confirmations and replay checks with exits `[0, 0]`.
These are fresh final-source runs. They do not re-label an earlier executable.

| Final receipt or log | SHA256 |
| --- | --- |
| `rust1100-strict-final/command.log` | `8231348c9cd642716730cf11ec8fe9976b652b35cc07c4b6b6b0c64fec927efb` |
| `fee-estimator-after/command.log` | `782976aeda33b585050eb000617f5625419dd1fe802e8c2d514028e2fd62e3a2` |
| `addrman-after/command.log` | `1c2a47bb4eb0571e56ab13b2957f8a4653e90712989453a044b5d15f6359c141` |
| `build-final/command.log` | `2efa80b35676886c50eeeddadf8d03275a1b48b06850eb80606f2f3ef513a8b3` |
| `final-runtime/mounted-staging/keyless-regtest.json` | `14662672f63a67d52610098c262ebae1f9ad4ac1e329414e606ab43a598abade` |
| `final-runtime/adversarial/patched/report.json` | `cda0ceabb3f0ef70879e8f83276bf582687affc49082b195d561498cb27a2435` |

The fee and address-manager changes affect optional estimation/discovery
owners, without granting them chainstate transition authority (`SYNC-03`).
The pending-reference and accounting oracles remain with their existing
owner tests. The checkpoint and validation ownership/`SYNC-04`/`SYNC-05`
analysis above remains unchanged. Current GitHub results belong to the
published head's checks; historical ZMQ causality remains unproven.

## Hosted artifact and workflow syntax repair

The hosted funded job at published source `3906a6e187d80f18b050640de1893252592b05ab`
passed in [run 43333152632](https://github.com/patrickdugan/bitcoin-rs/actions/runs/43333152632).
Its test merge `c3e007109ae1008d73e8b0aa5fc918155cabca7f` has the same tree
`e9c57b46b1fb5eeb45634178e14c22461b0d5de2`. The downloaded archive matched all
1,301 source blobs and executable modes against that tree. It contains a
different hosted executable, SHA256
`fe506c638478d173edd267422856b9fb02c8ab424b694b6c81554dce2a48caa6`.
Its staged receipt records two 98,000-sat payouts, all 29 rejections, restart,
zero peers and exits `[0, 0]`. All linked stage-log and receipt hashes passed.
This artifact is distinct from the locally built executable above.

The downloaded artifact ZIP SHA256 is
`86dbe22d7bd4a5f3002443c52fb77fb1e3ad3cfc7db24e9c775c2a4cbfb88e24`.
Local verification is `ci-3906-regtest/verified.json` in the repair packet.
The hosted Clippy, formatting, dependency and contract jobs at this head passed.
Both Keyless jobs completed successfully. The semantic artifact archive SHA256 is
`d8f64ddf6fdc487b33c22f14b2af8d95dc37c601ed7ab3d966aebd37bad16356`.
Independent validation checked every stage-log digest and counted 35 Python
and 511 Rust passes. The receipt is `ci-3906-tests/verified.json`.

An additional [push check](https://github.com/patrickdugan/bitcoin-rs/actions/runs/43333146583)
failed before creating jobs. Its annotation identifies invalid YAML at
`.github/workflows/main.yml:262`. That file at `3906a6e18` is byte-identical
to base `dev` at `9b8e91ae1aadfaad08e7fccbfa895bcbf41c6620`.
The plain `run` scalar contains `::` followed by spaces, which YAML treats as
mapping syntax. Existing PyYAML 6.0.3 reproduced the parse failure at line 262.

The repair changes this scalar to a block scalar. The complete YAML then parses.
The validation receipt checks the exact test command, main-only push trigger,
manual trigger and read-only contents permission. They are unchanged.
No job, assertion, test filter or permission was removed or broadened.
This syntax repair has no node synchronization or runtime impact: it changes
only the representation of the existing CI command. The runtime source and
binary identity above remain applicable. The receipt is
`workflow-yaml-validation.json`; its before/after file SHA256 values are
`95b794fdc5af87e688131852cbb449485877faf9f03e2c04aca234d1d3c862fa` and
`aadf04d4bd016ef2cafbecf0d40fb51455f989a7553b4a451f72e0f60f10cc03`.

## ZMQ finding remains unlocalized

The [original broad CI run](https://github.com/patrickdugan/bitcoin-rs/actions/runs/43249495342)
recorded SIGSEGV in
`zmq_publisher_handle_reports_active_metadata`. Its cause is not proven to be
inherited or fixed. This change contains no speculative ZMQ runtime edit.

The [current-code broad run](https://github.com/patrickdugan/bitcoin-rs/actions/runs/43333152503)
reproduced this SIGSEGV on Rust 1.100. Its node profile completed 383 passes,
one crashed test and two existing subprocess-entrypoint skips. The complete
job log is retained as `github-test-crates-43333152503.json`.
The green Keyless matrix does not override this failed broad gate.

The PR's existing failed `test-crates` step remains unchanged. A failure-only
diagnostic on this research branch collects up to six bounded native traces
of the same test executable and preserves the executable, trace and digests.
It uses an existing GDB or a signal-backtrace library built by the existing C
compiler, and installs no software. Its receipt explicitly
sets `validation_pass` to false. It cannot convert the failed gate to success.
No test or runtime implementation is changed by this diagnostic. The optional
notification owner still has no chainstate transition authority (`SYNC-03`).

Run [43336319575](https://github.com/patrickdugan/bitcoin-rs/actions/runs/43336319575)
at `074a236ff4f3f3c85f28b6c2592c459c80eaa721` reproduced the same 383-pass,
one-crash node result. The initial diagnostic found no installed GDB and
stopped without installing it. The compiler-backed fallback addresses that
tool prerequisite and does not change the failing gate.

The original test passed 100 nextest repetitions, 1,000 trials from an immutable
test binary with four bounded child processes, and 40 heap-perturbed trials.
The original complete node profile also passed all 384 tests. The repaired
profile's ZMQ check passed. A separate probe using the same vendored libzmq
4.3.4 passed 2,000 two-socket context lifecycles. No local SIGSEGV was observed.
The frozen test binary SHA256 is `0b4c0645f90d79b9e200e0cd4c12dcf8aedb00b094cf7bd7b952eb237a4244f6`.

The failing CI host used Ubuntu 26.04.1, nextest 0.9.143 and mold
2.40.4+dfsg-2.1ubuntu1. Those differ from the installed local environment.
A diagnostic backtrace or local reproduction of that failure is still needed to
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
