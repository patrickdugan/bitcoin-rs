# NestedMuSig2 staging

This tool implements the NestedMuSig2 signing rounds and spends a Taproot
output through the node's existing BIP340/BIP341 validation. It runs as a
separate process. Node consensus, synchronization, persistence, and RPC
ownership remain in their existing crates.

The draft is [BIP PR #2297](https://github.com/bitcoin/bips/pull/2297), pinned
at `4523ee0eed72f2367a1d1774941f70b2aca5af43`. The implementation follows the
[conformance follow-up](https://github.com/BEULAHEVANJALIN/bips/pull/2), pinned
at `44e9d2518e7fa9073fd904f6224b221057c48c2c`, including its nonce-first,
X-only intermediate hash and root tweak corrections. The fixture provenance
is recorded beside the conformance tests.

The command-line profile uses four fresh signing keys. Two leaves form each
subgroup, and the root aggregates the two subgroup keys. Every key contributes
to each signature. The root receives the standard Taproot key-path tweak with
an empty script tree. Intermediate nodes preserve their compressed key parity.

All four participants run in one local process for transaction staging. The
library exposes individual nonce, partial signing, and aggregation operations
for a future coordinator. A distributed signer transport and independently
operated custodians remain follow-up work.

## Build and verify

Run these commands from the repository root:

```sh
cargo test --locked -p bitcoin-rs-nested-musig2 --features conformance
cargo clippy --locked -p bitcoin-rs-nested-musig2 --all-targets --features conformance -- -D warnings
python3 -m unittest discover -s scripts/tests -p test_nested_musig2_staging.py
cargo build --locked --profile quickstart -p bitcoin-rs-nested-musig2
cargo build --locked --profile quickstart -p bitcoin-rs --no-default-features --features fjall
```

The `conformance` feature exposes deterministic nonce generation and nonce
import for external vectors. Ordinary builds omit those entry points. The
command-line signer always obtains entropy from the operating system.

Staging CI selects Rust 1.99.1 explicitly through `RUSTUP_TOOLCHAIN` and records
the compiler version in the bundle. The repository's general PR checks use
the current stable compiler.

The library sorts each aggregation's compressed keys according to BIP327 and
retains duplicate occurrences. It bounds path depth, participant count, and
message length. Root tweaks use BIP327's plain and X-only tweak rules. The
intermediate hash is `NestedMuSig/aggnoncecoef(internal_nonce || xonly_key)`;
the root nonce coefficient keeps the BIP327 message binding. Intermediate
infinity points cause an error, while a finite generator point remains valid.
Only the root applies the final `challenge * key_parity * tweak_accumulator`
correction.

Secret nonces have no clone or serialization interface. Signing takes ownership
of the nonce and erases it on success or error. Generation binds the leaf key
and, when supplied, the final aggregate key and message. The transaction tool
knows both before generation. A restarted signing process generates fresh
nonce material from the operating system. The tool has no persisted nonce
state that a process can restore.

The tests cover pinned independent vectors, malformed encodings, signing
failures, and the ownership boundary. CLI tests check key-file permissions,
exclusive creation, network binding, fee caps, and fresh signatures after
repeating an authorization. The live lane supplies external Bitcoin Core
verification for the transaction and the block that confirms it.

## Regtest CI

Install the repository's pinned Bitcoin Core reference, then run the harness:

```sh
scripts/install-bitcoind.sh
python3 scripts/run-nested-musig2-regtest.py \
  --bitcoin-rs target/quickstart/bitcoin-rs \
  --bitcoind "$(scripts/install-bitcoind.sh --print-path)" \
  --signer target/quickstart/nested-musig2 \
  --output target/nested-musig2-regtest
```

The output directory must be absent. Each run creates private temporary node
directories and fresh keys, then removes them when the processes stop. The
bitcoin-rs node uses native validation. Both nodes bind RPC to loopback, and
the harness checks that they have zero peers. Bitcoin Core receives mined
blocks through `submitblock`.

The harness mines 101 blocks to the nested Taproot address on bitcoin-rs and
checks that Core accepts the same chain. It spends the first matured coinbase
to a separately generated destination, paying exactly 1,000 satoshis. Both
nodes must reject an altered signature and accept the original transaction
with the same transaction ID, virtual size, and fee. The native node mines the
spend into block 102. Core must accept that block, after which both nodes must
show the funding output as spent and the new output as confirmed.

`.github/workflows/nested-musig2.yml` runs this lane and retains its public
evidence in the runner's temporary directory, outside Cargo's build cache.
The output directory contains:

| File | Contents |
| --- | --- |
| `public-tree.json` | Public leaf and subgroup keys, the root tweak, output key, address, and genesis hash |
| `signed-transaction.json` | Authorized prevout, destination, amounts, signature, sighash, and serialized transaction |
| `receipt.json` | Source revision and dirty-state flag, binary SHA256 hashes, each node's verdict, and the confirmed block |
| `bitcoin-rs.log`, `bitcoind.log` | Process logs for the isolated run |

Private keys and secret nonces stay outside this output directory. CI artifacts
must select the output directory rather than the temporary node directories.
A local receipt with `source_dirty: true` describes an uncommitted working
tree. Use the clean CI receipt to associate evidence with a published commit.

A successful CI run also publishes `nested-musig2-linux-x86_64` with the node,
signer, testnet runner, source commit, binary checksums, and regtest receipt.
Extract its tarball and run `sha256sum -c SHA256SUMS` before use. These binaries
are built on Ubuntu 24.04 for x86_64 Linux. The bundle records the build's Rust
and libc versions; build from source when your platform differs.

In the commands below, a bundle user can replace `target/quickstart/bitcoin-rs`
with `bin/bitcoin-rs` and `target/quickstart/nested-musig2` with
`bin/nested-musig2`. The Python scripts keep their `scripts/` paths. Packaged
receipts use `source-sha.txt` for the source revision and report `source_dirty`
as null because the bundle has no Git working tree. Each receipt also records
the signer binary's hash.

## Local testnet4 follow-up

The testnet wrapper checks a running, fully synchronized local node. It uses
testnet4 explicitly and verifies the genesis hash. The CLI accepts `regtest`
and `testnet4`; each key file records its network.

Create the staging directory, then start a local node in one terminal:

```sh
install -d -m 700 target/nested-musig2-testnet4
target/quickstart/bitcoin-rs \
  --network testnet4 \
  --data-dir target/nested-musig2-testnet4/node \
  --rpc-bind 127.0.0.1:48332 \
  --p2p-listen 127.0.0.1:48333 \
  --validation-engine native
```

The node generates its RPC cookie in the data directory. An existing Core
testnet4 node also works when its RPC URL and cookie path are supplied.

In another terminal, generate fresh test keys and save the public funding
details:

```sh
target/quickstart/nested-musig2 init \
  --network testnet4 \
  --keys target/nested-musig2-testnet4/keys.bin \
  > target/nested-musig2-testnet4/public-tree.json
```

The key file contains four plaintext test secrets with mode `0600`. Creation
is exclusive, so repeating `init` cannot overwrite it. Use `info` with the
same arguments to recover the public address. Keep this file outside shared
artifacts and use disposable test funds for this experimental profile.

Fund the reported address manually and wait for confirmation. Record the
funding transaction ID, output index, exact value in satoshis, and your chosen
destination. Set the following shell variables to those values before running
the wrapper: `NESTED_FUNDING_TXID`, `NESTED_FUNDING_VOUT`,
`NESTED_FUNDING_SAT`, `NESTED_DESTINATION`, `NESTED_FEE_SAT`, and
`NESTED_MAX_FEE_SAT`.

```sh
python3 scripts/run-nested-musig2-testnet.py \
  --network testnet4 \
  --signer target/quickstart/nested-musig2 \
  --keys target/nested-musig2-testnet4/keys.bin \
  --rpc-url http://127.0.0.1:48332 \
  --cookie target/nested-musig2-testnet4/node/.cookie \
  --txid "$NESTED_FUNDING_TXID" \
  --vout "$NESTED_FUNDING_VOUT" \
  --amount-sat "$NESTED_FUNDING_SAT" \
  --destination "$NESTED_DESTINATION" \
  --fee-sat "$NESTED_FEE_SAT" \
  --max-fee-sat "$NESTED_MAX_FEE_SAT" \
  --output target/nested-musig2-testnet4/review-1
```

This command fetches the UTXO from the local node, checks its script and amount,
builds a single-input, single-output transaction, and signs its BIP341
`SIGHASH_DEFAULT` digest. It also checks the signature with libsecp256k1 and
compares its output key with rust-bitcoin's Taproot derivation. The node must
accept a `testmempoolaccept` preview before the review files are written.

Inspect `signed-transaction.json` and `receipt.json` before the local
broadcast step. Rerunning the command with a new output directory and the
explicit `--broadcast` flag submits the authorized transaction. That flag is
the only broadcast path in the testnet wrapper. Regtest CI never invokes the
testnet wrapper.

RPC credentials are read from the cookie file. The wrapper permits literal
loopback HTTP endpoints and refuses redirects. It checks confirmed output
availability again immediately before an explicit broadcast. A chain reorg
or competing spend can still change acceptance after that check.

## Experimental scope

The staging profile fixes nesting depth at two. The core's bounded path API
also supports deeper conformance cases; passing these cases establishes
agreement with the pinned reference for those inputs. Production deployment
still requires review of the draft's nested security proof, its BIP327
coefficient optimization, and the X-only intermediate hash binding.

The CLI keeps each secret nonce inside one process and creates a new nonce for
every attempt. It does not implement a distributed authorization service,
persistent hardware signer, or recovery protocol for cloned signing state.
Those systems need their own protection against rollback and concurrent use.
Mainnet use, threshold signing, subgroup tweaks, script-path spending, and
wallet coin selection are outside this staging profile.
