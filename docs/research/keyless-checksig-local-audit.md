# Independent local Keyless CHECKSIG audit

The runtime source is PR #2 at
`e616005407071dc1241bd17f891522f663cb1b34`, with tree
`89dba8c8046b41bb3a9a494cb33995db8024414f`.
This work uses a separate checkout. It does not use the OP_MULADDMOD branch.

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

There is no runtime synchronization change. The new tools call the existing RPC
and fixture boundaries. The original staging lane owns the selected SYNC-04
and SYNC-05 behavioral checks.

## Sources

- [Pinned native integration](https://github.com/patrickdugan/bitcoin-rs/pull/2)
- [BIP94 Testnet4 identity](https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki)
- [BIP141 witness commitment](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
- [Native proposal and staging guide](keyless-checksig.md)
