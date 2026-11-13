# Independent local Keyless CHECKSIG audit

This document records the initial pinned audit. The subsequent runtime repair
and current integration evidence are in [the integration repair report](keyless-checksig-integration-repair.md).

The initial runtime source was PR #2 at
`e616005407071dc1241bd17f891522f663cb1b34`, with tree
`89dba8c8046b41bb3a9a494cb33995db8024414f`.
This work uses a separate checkout. It does not use the OP_MULADDMOD branch.

## Observed local result

The complete exact-head run passed on the MSI through Ubuntu 24.04 on WSL2.
It started at `2026-11-12T16:10:02.827822+00:00` and finished at `2026-11-12T17:56:12.399613+00:00`.
The source stayed clean at the pinned runtime revision throughout the run.

The original head passed 34 Python tests and 511 Rust test executions. The
repaired audit code passed 35 Python tests at
`e72051831d301c73f91d71cedc5ac145df0de534`. Counts include repeated common Rust cases
across feature profiles. There were no failed or ignored tests in these final
receipts.

| Selected Rust step | Passed executions |
| --- | ---: |
| `sighash` | 10 |
| `flag-off` | 83 |
| `txcommit-only` | 93 |
| `cat-only` | 85 |
| `script` | 95 |
| `consensus-flag-off` | 3 |
| `consensus` | 136 |
| `mempool` | 2 |
| `node` | 1 |
| `sync` | 1 |
| `sync-dispositions` | 1 |
| `sync-publication` | 1 |
| Total | 511 |

The locally built executable is version 0.15.0. Its SHA256 is
`e234e799428631c2f8ee4f1d62a0d98914cd48824e3cd55519cbf045ce6d9bfd`. The preserved copy is
`../evidence/artifacts/bitcoin-rs-e616005` relative to this checkout.
Its build command used `--locked --jobs 2 --profile quickstart`, the `fjall`
backend, both regtest experiment features, and no default binary features.
The complete command is in `full-01/report.json`.

The build used `rustc 1.99.1 (58cf8f9c3 2026-10-13)` and
`cargo 1.99.1 (5f94df478 2026-08-27)`, Python 3.12.3, and Git 2.43.0.
The host reports `Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39`. The exact tool versions and recorded
environment flags are retained in the environment receipts.

### Funded and adversarial observations

The strict replay used the same local executable and the repaired helper.
It funded three 100,000-sat reserves at height 102 and confirmed two
98,000-sat payouts at height 103, with 2,000-sat fees. Both recipient choices
were eligible from the same reserve before spending. The policy was 191 bytes;
its selected key version was 2, and its reserve paths used no Script signatures.

Funding transaction: `0b27cd4d517a6442979caf49a4a9cda8910aa8106755fcb0617019c8d7367037`.

| Recipient index | Confirmed payout transaction | Sats |
| --- | --- | ---: |
| 0 | `2badefb8f161e423cd4c4736bd3324e3f89bd80704114863d2928395ee6a1ffc` | 98000 |
| 1 | `e7ea52a32795e2dc6db2364645b6d7e5a5c1a4e75c44d0ea225651c85698f447` | 98000 |

All 29 original rejection cases passed. Policy-only rejection cases also
received the fixture's separate block-validation checks. The added campaign
recorded 36 Script block rejections with unchanged heights, 12 positive cases,
and seven confirmed transactions. Five positive cases were admission dry runs.
Spent-input replay was rejected both before and after restart.

The generic annex cases bound the verified public block-50,000 hash through
each of CHECKSIG, CHECKSIGVERIFY, and CHECKSIGADD. The fixed payout policy
continued to reject annexes. Recommitted version, sequence, locktime, input
count, and input-index changes were accepted where the policy permits them;
stale commitments failed. Split payouts and inserted outputs failed even with
rebuilt transcript witnesses. These results do not imply that every transaction
field is restricted by the policy.

Eight repeated checks consumed 400 units from an independently calculated
411-unit witness budget and confirmed. Nine checks required 450 units from
447 available and were rejected. This checks the draft 50-unit rule; it is not
a production cost measurement.

The strict local baseline and added campaign each recorded shutdown codes
`[0, 0]` across restart. Confirmed payouts remained, spent reserves stayed spent,
and unused reserves remained available. All observed peer counts were zero.

### Public Testnet4 and stock controls

The public genesis matched
`00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043`. Downloaded blocks 0, 1, 2, and 50,000 supplied
four headers and 15 transactions. Header hashes, proof of work, transaction
merkle roots, and the block-50,000 witness commitment verified. Header,
transaction-body, and witness mutations were independently rejected.

A fresh stock Testnet4 node accepted public blocks 1 and 2 with wallets and
P2P connections disabled. It observed zero peers and exited zero. The higher
block received integrity checks, not a complete history or Script replay.
The explorer's height mapping remains a source assumption for that fixture.

The installed Core 31.1 binary has SHA256
`986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`. Its bytes matched the existing release
archive, whose checksum matched the official HTTPS SHA256SUMS file. Release
signatures were not verified and no keys were imported. The provenance receipt
identifies the archive and checksum bytes.

The same stock Core binary confirmed the separate regtest controls for a
one-byte candidate under the unknown TXCOMMIT key and for CAT's old OP_SUCCESS
behavior. Relay policy rejected both. These synthetic spends occurred only on
regtest. The native feature-selection tests also excluded both research flags
on Testnet4 and the other public networks.

The published CI executable was replayed locally as an additional comparison.
Its SHA256 was `44b8ec18f902042f67b015d87135a14609a37d649994ec6a473dec700a5cca42`.
Its declared source commit was `cc2a4016e65ebdbe3231f67541b6f014bee3e08a`.
All 1,297 archived source blobs matched the pinned runtime head, including
file modes, and all recorded artifact-stage digests verified. Its local strict
baseline and adversarial replays passed. This CI-built executable is identified
separately from the locally built executable.

### Discovered failure and scoped repair

An early added campaign used node data on the WSL `/mnt/c` mount. It completed
the transaction checks and restart, but the node log showed failed checkpoint
publication and shutdown exit 1: `Invalid argument (os error 22)`. The original
shared helper discarded that exit code, so the initial campaign's success
report was invalidated as final evidence. Its receipt, log, and review marker
remain preserved in `ci-adversarial-01`.

A one-block reproduction also exited 1. A real-child-process regression then
failed against the original helper because a nonzero child exit was accepted.
The repair makes the shared helper record exits and reject nonzero status,
including failure during final cleanup. The new campaign uses native Linux
temporary node data and retains its logs in the Windows workspace. All final
shutdown checks passed. The underlying Rust checkpoint behavior on `/mnt/c`
was not repaired during that initial phase. The follow-up repair report above
records the later Rust repair and verified Windows-mount recipe.

Four Python preflight subcases also exceeded their existing 10-second limits
when Git scanned the Windows-mounted checkout. The same suite passed from a
native Linux checkout without changing those limits. No Rust source,
dependency file, consensus rule, or existing broad CI gate was changed by the
local repair.

The normal exact-head CI run `43249495342` remains failed: `test-crates` logged
SIGSEGV in `zmq_publisher_handle_reports_active_metadata`. That test's source
is unchanged from the base. Its cause was not established or repaired here;
an inherited failure is not proven merely by an unchanged test path. The
separate Keyless results do not make the broader CI gate green.

### Retained evidence and remaining limits

The evidence directory is beside this checkout at `../evidence`. It contains
`verified-summary.json`, `manifest.sha256`, the tested executable, the exact
source archive, a complete Git bundle, public block bytes, raw adversarial
transactions and positive blocks, all stage logs and receipts, the stock Core
provenance receipt, and the failed shutdown reproduction. `native-replays.json`
records both final replay commands, bounds, exit codes, durations, and log hashes.
Every recorded stage-log and fixture-receipt digest was checked.

At initial audit completion, the original runtime source remained at its exact
SHA. The audit repair lives on the separate local `audit/keyless-msi-e616005`
branch. Existing unrelated
MULADDMOD checkouts were left untouched, and initial and final status receipts
were retained. During that initial phase, no branch was pushed, no PR was
published or merged, and no experimental transaction was sent to a public
network. No software installer
or paid API was used.

NUMS P2TR, P2MR, computation-proof application binding, activation, and cost
calibration retain the boundaries below. The available tools exposed no native
goal control; the explicit delegated GOAL was the execution contract. No
native `/goal` activation is claimed.

## Reproduce

Use the existing Linux or WSL toolchain. Keep an exact clean runtime checkout
separate from the checkout that contains these audit tools. Every output path
must be new. No package installation is required by either Python tool.

Run the original staging command in the clean runtime checkout:

```sh
python3 scripts/research/keyless_checksig_stage.py \
  --profile full --output /path/to/evidence/full \
  --jobs 2 --timeout 900 --build-timeout 1800
```

Acquire public fixtures and verify them with an installed stock Core binary:

```sh
python3 scripts/research/keyless_checksig_testnet4.py \
  --source /path/to/audit-checkout \
  --output /path/to/evidence/public \
  --core /path/to/stock/bitcoind
```

To repeat without a public download, add
`--fixtures /path/to/evidence/public` and select a new output path.
The tool verifies the Testnet4 genesis before downloading further blocks.
It checks blocks 0, 1, 2, and 50,000: header hashes, proof of work, transaction
merkle roots, transaction IDs, and the BIP141 witness commitment when present.
Header, transaction, and witness mutations must fail at their integrity boundary.
A fresh stock node uses Testnet4, disables wallets, listens on no P2P socket,
disables outbound connections, and accepts public blocks 1 and 2 through RPC.
Block 50,000 receives commitment checks, not a full history or Script replay.
Its height mapping retains the public explorer as a source assumption.

Run the live adversarial campaign with the locally built runtime:

```sh
timeout --kill-after=15s 900s \
  python3 scripts/research/keyless_checksig_adversarial.py \
  --source /path/to/audit-checkout \
  --output /path/to/evidence/adversarial \
  --binary /path/to/clean-runtime/target/quickstart/bitcoin-rs \
  --core /path/to/stock/bitcoind \
  --public-report /path/to/evidence/public/report.json
```

The stock and patched node options can also run separately. The campaign starts
fresh regtest data, verifies the genesis, and checks zero connected peers.
Node data uses a native Linux temporary directory; logs and receipts can use
the Windows workspace. Every observed node shutdown must return zero.
It retains raw funding and spend transactions, positive blocks, dry-run results,
block rejection errors, height checks, and restart observations.

The stock controls distinguish relay policy from consensus. An unknown 33-byte
key accepts a nonempty one-byte candidate in a block. The CAT byte retains its
OP_SUCCESS rule. Standard relay rejects both controls.

The patched campaign exercises the fixed payout policy and separate generic
TXCOMMIT leaves. It checks stale and recomputed version, locktime, sequence,
added-input, and input-index commitments; alternate transcript fragmentation;
split and reordered outputs; all three signature opcodes with an annex derived
from a verified public Testnet4 block; annex and candidate mutation; failed
checks followed by inversion; empty candidates; CAT underflow; and signature
budget exhaustion. It checks spent-input replay before and after restart.

Each report identifies the harness and binary by SHA256. The original staging
report owns executed test counts and runtime build provenance. The added tools
do not change the original runner's strict 29-case fixture contract.
The shared fixture helper now rejects a nonzero node exit. A real child-process
regression failed before that repair. Its isolated fake server now exits zero
on SIGTERM, matching the node's successful-shutdown contract.

## Research limits

Public Testnet4 does not select these experimental flags. Its stock block
validation is separate from the synthetic opcode controls on regtest. No
experimental transaction is sent to public Testnet4.

The payout outputs use NUMS P2TR, not P2MR. The generic annex tests check the
primitive; they do not extend the fixed payout policy to authorize annexes.
Recommitted fields demonstrate permitted transaction shapes, not a restriction
on all transaction fields. These tools establish no general computation-proof
application binding, BIP allocation, activation, or production cost calibration.

The initial audit tools made no runtime synchronization change. They call the
existing RPC and fixture boundaries. The original staging lane owns the selected SYNC-04
and SYNC-05 behavioral checks.

## Sources

- [Pinned native integration](https://github.com/patrickdugan/bitcoin-rs/pull/2)
- [BIP94 Testnet4 identity](https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki)
- [BIP141 witness commitment](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
- [Native proposal and staging guide](keyless-checksig.md)
- [Core 31.1 official checksums](https://bitcoincore.org/bin/bitcoin-core-31.1/SHA256SUMS)
