# Experimental OP_MULADDMOD build

This fork integrates Spiral's bounded modular arithmetic draft into the native
transaction interpreter. The opcode byte `0xf0` is private to this experiment.
It is OP_SUCCESS240 under ordinary BIP342 rules. There is no assigned BIP number
or agreed opcode allocation.

## Build and isolation

```
cargo build --locked --release -p bitcoin-rs --no-default-features \
  --features fjall,experimental-muladdmod-regtest
```

This feature selects the rule for **regtest only**, when witness and Taproot
validation are active. The default build and all public networks retain their
existing activation rules. The feature has no deployment bit or activation
height on mainnet, testnet3, testnet4 or signet. Do not reuse an existing regtest
data directory or connect this research network to ordinary regtest peers.
All participants in a test network must use the same rule set.

Start with a fresh directory, loopback ports, and the native engine:

```
./target/release/bitcoin-rs --network regtest \
  --validation-engine native --storage-backend fjall \
  --data-dir /tmp/bitcoin-rs-muladdmod-new \
  --p2p-listen 127.0.0.1:19444 --rpc-bind 127.0.0.1:19443
```

The kernel backend does not implement this opcode. Configuration refuses that
backend for the experimental regtest network. The consensus adapter also
rejects experimental flags before it can mask them into Core's supported flag
set. The ordinary native and kernel behavior remains available on other
networks. Never fund an unactivated OP_SUCCESS240 script on a public network.

## Consensus surface

`... a b c m OP_MULADDMOD -> ... (a*b+c) mod m`

Operands use unsigned little-endian bytes. The minimally encoded modulus is
2 through 2^256-1 and occupies 1 through 32 bytes. Each residue uses exactly
that width and is strictly below the modulus. The result has the same width.
Composite moduli are supported. The implementation uses a 33-byte accumulator
and bounded binary multiplication; it has no external big-integer dependency.

The interpreter charges 50 units against the **same per-input counter** that
charges nonempty tapscript signatures. This price is provisional. The existing
witness serialization, including annex and CompactSize lengths, initializes
that counter. Skipped branches incur no arithmetic charge. An activated opcode
loses its early-success semantics, including the old initial-stack-limit bypass.
Other OP_SUCCESS bytes retain their behavior. Legacy and witness-v0 scripts
retain their existing opcode rules.

The script crate exposes `VerifyFlags::EXPERIMENTAL_MULADDMOD` as an explicit
opt-in for consumers. Its `experimental-muladdmod` Cargo feature must also be
present; requesting the flag in an ordinary build fails closed. `MANDATORY` and
`STANDARD` never include the experimental bit. Mempool policy combines STANDARD
with the next-block flags. Execution-cache keys already include the full flag
bits and have an explicit regression for the experimental rule set.

## Reproduce

```
cargo test --locked -p bitcoin-rs-script
cargo test --locked -p bitcoin-rs-script --features experimental-muladdmod
cargo test --locked -p bitcoin-rs-consensus --features experimental-muladdmod-regtest
cargo test --locked -p bitcoin-rs-mempool --features experimental-muladdmod-regtest muladdmod
cargo test --locked -p bitcoin-rs-node --no-default-features \
  --features fjall,experimental-muladdmod-regtest muladdmod
```

The arithmetic test requires Python 3. It reproduces all 12,037 valid and 293
malformed operand vectors from Spiral v0.2 using an independent Python integer
oracle. Rust tests also verify real rust-bitcoin-created Taproot commitments
through both native complete-prevout APIs. They cover malformed encodings,
legacy/v0 isolation, control-block mutation, skipped branches, other success
opcodes, Script negative zero, MINIMALIF, and mixed signature/arithmetic budgets.

The dedicated workflow builds the node binary and checks the flag-off script
suite separately. Its artifacts record the exact source revision. A green
arithmetic test does not establish full-block worst-case validation cost.

## Synchronization and proof boundary

This change touches authoritative native input-script validation, the consensus
flag selector, and mempool policy. It can affect SYNC-04 rejection and SYNC-05
validated progress on the opt-in regtest network. Existing commit, rollback,
reorganization, storage and publication owners are unchanged. The regression
lane runs the existing chainstate invalid-middle-block valid-prefix proof.
Full restart, reorganization, cross-node interoperability and denial-of-service
campaigns remain separate evidence obligations.

This is an arithmetic primitive. It supplies no trace authentication, proof
soundness, challenge inclusion guarantee or recovery covenant. The host-side
BitVM trace model from Spiral is not compiled into a complete bridge here.
Funding/admission still needs authenticated operands and the correct modulus.
An invalid encoding aborts Script; a fraud protocol needs its own successful
encoding-challenge branch.

Sources:
- Spiral v0.2: https://github.com/patrickdugan/Spiral/pull/14
- Pinned source: 7f5ad9f95fce8c40919e360000ca86c7119ceb5c,
  BIPSpace/Bounded-Modular-Arithmetic/
- BIP342: https://bips.dev/342/

## Funded claim fixture

The [authenticated claim dispute](muladdmod-dispute.md) exercises SHA256-bound
operands, beneficiary-authorized recovery and delayed operator settlement
through real regtest transactions. It also records the missed-window
counterexample. Its admission and signature requirements remain explicit.
