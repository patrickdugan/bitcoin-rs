# Keyless CHECKSIG native integration

This branch integrates the Keyless CHECKSIG research proposal into the native
`bitcoin-rs` interpreter. The source proposal is
[Spiral Keyless CHECKSIG](https://github.com/patrickdugan/Spiral/blob/cfafbec4ae072b859f0140b2487baac14fac3a44/BIPSpace/Keyless-CHECKSIG/bip-keyless-checksig.md).
Its BIP number, key selector, and key version remain unallocated research values.

The transaction primitive checks a digest supplied by Script against the actual
spending transaction's Taproot signature hash. A surrounding Script program
must establish which transaction is authorized. The live fixtures exercise
a committed recipient allowlist and a
[bounded state machine](keyless-state-machine.md) whose checked result selects
its payout and successor program.

## Native rule

The selector is exactly 33 bytes:

```text
02 || SHA256("BIPSpace/Keyless-CHECKSIG/TXCOMMIT-draft")
```

The selected Tapscript key type applies to `OP_CHECKSIG`, `OP_CHECKSIGVERIFY`,
and `OP_CHECKSIGADD`. It commits `key_version = 2`, epoch zero, fixed
`SIGHASH_DEFAULT`, and script-path `ext_flag = 1`. The active tapleaf and last
code-separator position come from the interpreter. Annex hashing follows
BIP341. All input outpoints, amounts, scripts, sequences, and ordered outputs
are committed under the default hash type.

| Candidate | Result under the selected rule |
| --- | --- |
| Empty | Existing empty-signature behavior: false, CHECKSIGVERIFY failure, or an unchanged CHECKSIGADD integer. |
| Exactly 32 bytes, equal to the actual digest | Successful check. |
| Nonempty, with a different length or digest | Script aborts immediately. |

Every nonempty check consumes 50 units from the existing Tapscript per-input
signature budget. The caller cannot select another hash type with a trailing
byte. Ordinary Schnorr keys and unmatched unknown key types keep their existing
rules. Standard policy recognizes the exact selected key only when the
experimental flag is active.

Immediate abort preserves the intended soft-fork restriction: older BIP342
validation accepts a nonempty candidate for an unknown key type. Letting a
failed candidate produce false could make an enclosing `OP_NOT` succeed under
the new rule. The tests exercise this failure path for all signature opcodes.

The primitives crate owns the signature-message serialization and its component
caches. Its existing method selects key version zero. The explicit-version
method serves the experimental caller through the same implementation. Four
independently hashed transcript vectors cover versions zero and two, including
annex and code-separator binding; the ordinary transcript matches an existing
BIP342 pin.

## Feature and network boundary

| Feature | Purpose |
| --- | --- |
| Script `experimental-keyless-checksig` | Makes TXCOMMIT available to an explicit interpreter flag. |
| Node `experimental-keyless-checksig-regtest` | Selects that flag on regtest after Taproot validation is active. |
| Script `experimental-op-cat` | Separate bounded Tapscript concatenation companion. |
| Node `experimental-op-cat-regtest` | Selects the CAT companion on regtest. |

Both live fixtures need both node features. Each script feature also
needs its corresponding verification flag. An unsupported requested flag fails
closed. `MANDATORY` and `STANDARD` contain neither research flag. Public-network
activation rules retain their existing selections.

CAT concatenates two executed Tapscript stack items and enforces the 520-byte
element limit. Its activated byte loses the corresponding OP_SUCCESS behavior.
Other OP_SUCCESS bytes and the legacy and witness-v0 rules keep their existing
behavior. The feature matrix tests each companion separately and together.

The native engine owns execution. The Core-kernel adapter rejects either
research flag before converting flags to the kernel's supported set. Node
configuration also rejects the kernel engine on a selected research regtest
network. Mempool policy receives the next-block flags, and the execution cache
distinguishes complete flag sets.

## Funded payout fixture

[`keyless_checksig_rpc.py`](../../scripts/research/keyless_checksig_rpc.py)
creates fresh regtest outputs and exercises the policy through real RPC calls.
Each reserve uses an ordinary P2TR output with the BIP341 NUMS internal point
and one executable policy leaf. The reserve paths use no signature. The NUMS
construction retains the discrete-log assumption that its key-path signing
secret is unknown. P2MR requires a separate native implementation and review.

The policy commits a two-recipient SHA256 Merkle root and a 98,000-sat payout.
Witness data selects a recipient after funding. Script verifies membership,
serializes the permitted output, and reconstructs its TapSighash. TXCOMMIT
compares that result with the consensus-owned transaction digest.

For this fixed default-hash, no-annex policy, the message splits into a
138-byte prefix, the 32-byte `sha_outputs` field, and a 42-byte suffix. Script
receives the prefix as 74-byte and 64-byte witness fragments, concatenates them,
and checks the reconstructed prefix and suffix lengths. The successful witness
therefore respects the existing 80-byte standard stack-item policy. Those checks
bind the policy's output hash to its actual BIP341 position. The primitive supports
annexes; this particular policy restricts its witness to the no-annex form.

The fixture mines 101 blocks and funds three 100,000-sat policy reserves at
height 102. Two reserves fund payouts, one to each recipient, at height 103.
Each spend pays a 2,000-sat fee. Before consuming a reserve, the fixture checks
that either recipient is eligible from the same outpoint. The 191-byte policy
has 29 rejection cases covering recipient and value changes, malformed proofs,
stale transaction context, and spent inputs.
Three witnesses hit relay policy first: the oversized stack item and both annex
cases. The fixture also submits each directly to block validation and checks
its Script rejection. A separate invalid-payout block attempt must leave the
chain height unchanged.
Restart checks inspect the consumed reserves, retained payout outputs, and
remaining policy reserve.

An updated witness can commit permitted changes to otherwise unrestricted
transaction fields. A rejected stale witness establishes digest binding; it
does not establish a policy restriction on every possible transaction shape.

## Bounded state-machine milestone

The [F17 state-machine compiler and campaign](keyless-state-machine.md)
authenticate a disclosed four-row computation against a committed old state.
The result selects a recipient, payout amount, and one of the precompiled
successor leaves. Two stages have four possible paths. The fixture funds
each path separately and confirms eight transitions at heights 103 and 104.
It tests both alternatives from the same unspent outpoint before spending.

The program constructs a strict single-input transaction message in Script.
Fresh wrong-old-state traces, replacement program identities, output changes,
and a funded extra input receive native rejection checks. Its 39
negative cases include direct block attempts, and restarts inspect the
committed output vectors. Every path uses NUMS P2TR and pays a 2,000-sat fee
per transition. The milestone page defines the complete relation, rejection
matrix, receipt fields, and limits of this finite successor construction.

## Run locally

Use Linux or WSL2 with Git, Python 3.10 or later, and the repository's stable
Rust toolchain and native build prerequisites. From a clean checkout:

```sh
python3 scripts/research/keyless_checksig_stage.py \
  --profile full --output target/keyless-staging/run-01 --jobs 2 \
  --timeout 900 --build-timeout 1800
```

The profiles are independent:

| Profile | Executed work |
| --- | --- |
| `offline` | Python fixtures, official signature-hash vectors, the F17 compiler's independent execution checks, and staging tests. |
| `semantics` | Signature-hash tests, script feature matrix, consensus flags, mempool admission, node engine selection, and existing rejection and publication proofs. |
| `regtest` | Build the native experimental executable and run `keyless-regtest` and `state-machine-regtest`. |
| `full` | All of the above. |

Each attempt requires a new output directory. `report.json` records the source
revision, executed commands, tool versions, test counts, log digests, and binary
identity. The two live steps retain `keyless-regtest.json` and
`state-machine-regtest/report.json`. An incomplete receipt, skipped test,
empty Rust test selection, RPC method error, or timed-out command fails the
run. Process groups are terminated on timeout or interruption. Each fixture
starts isolated temporary node data, uses full validation, removes inherited
node settings, disables DNS seeds, and
checks zero connected peers. Its keys and scripts are public test material.

`--timeout` limits each Python or RPC command; `--build-timeout` limits each
Cargo command. `--jobs 2` bounds Cargo build parallelism. The default values are
600 seconds, 1800 seconds, and two jobs. A directory within the checkout must be
ignored by Git. For work in progress, `--allow-dirty` records hashes of the
tracked diff and untracked files; retain that checkout to reproduce those
inputs. Final evidence should identify a committed revision.

A prebuilt executable can be supplied with `--binary`, `--binary-sha256`, and
`--binary-source`. The last argument requires a full commit SHA. Its source
identity is recorded as a declaration; the SHA256 check identifies the actual
executable bytes. Keep the original build receipt when using that option.

## Work order for a local agent

```text
Work on feat/keyless-checksig-regtest in patrickdugan/bitcoin-rs.
Read AGENTS.md, docs/research/keyless-checksig.md, and
docs/research/keyless-state-machine.md. Record the current revision and
preserve concurrent work. Use a fresh staging output path.

Run the offline profile, then the semantics and regtest profiles. Record
positive executed-test counts and both funded-fixture receipts. Check the
state-machine receipt for all four paths, eight confirmed transitions,
39 rejections, observed values and fees, and three zero daemon exit codes.
Reproduce a failure before changing code. Keep its logs and the smallest
regression that checks an independently specified result.

For further application work, define the statement and transcript encoding
for the selected proof system, then bind its checked result and old state
to the payout and successor program. Extending the finite F17 construction
to arbitrary dynamic states requires its own successor-commitment design
and adversarial evidence. Keep the complete Nova verifier and Circle-STARK
application statements identified separately from the disclosed F17 trace.

Keep public-network consensus unchanged and both experimental features
explicit. Push scoped fixes to this Keyless CHECKSIG branch with a normal
push after fetching current work. Leave its PR open. Report the commit,
staging receipt, executed checks, and remaining evidence requirements.
```

## Next evidence requirements

An application verifier must authenticate the same payout and state transition
that TXCOMMIT commits. The F17 milestone supplies this link for a fixed,
disclosed trace and precompiled successor leaves. General proof integration
must define and verify its own application statement. The existing Spiral
Nova adapter and Circle-STARK workbench retain their separate statement and
provenance records.

A general application needs an authenticated initial state and a construction
for arbitrary successor programs, canonical commitments, proof-fragment
availability, and a recovery rule for stalled multi-transaction verification.
Fee adjustments and reorg margins need measured transaction campaigns.
Selecting a production per-check cost requires cold-cache and worst-case
block measurements, including repeated
checks and failures late in script execution.

The change touches authoritative input validation and next-block mempool flag
selection, so it can affect `SYNC-04` rejection and `SYNC-05` validated progress
on the selected regtest network. Storage and commit ownership stay with their
existing modules. The staging lane runs the mapped
`apply_errors_classify_into_their_documented_dispositions` and
`tick_recovers_rejected_frontier_without_publishing_unapplied_blocks` proofs.
It also runs `a_window_with_an_invalid_middle_block_commits_only_the_valid_prefix`
and both funded fixtures' restart checks. Reorganization and interoperability
campaigns remain with their owning process lanes. The normal PR workflow owns
the repository-wide dependency, Clippy, and crate-test gates.

## Public Testnet4 replay

The same feature-enabled research executable can validate genuine Testnet4
blocks with both draft experiments disabled by network selection. Run this
wallet-free replay with zero public peers:

```sh
python3 scripts/research/keyless_checksig_testnet4.py \
  --source . --binary target/quickstart/bitcoin-rs \
  --fixtures scripts/tests/data/keyless-testnet4 --replay-height 12 \
  --output /tmp/keyless-testnet4-native-01
```

Use a fresh output directory. Replace `--binary` with `--core /path/to/bitcoind`
to run the stock Core control. The Core control also supports installed Windows
executables with `python`; it requests graceful RPC shutdown and requires zero
exit status. The full staging runner still requires a POSIX host for process
group cleanup.

The checked-in public fixtures include the contiguous blocks 0 through 12 and a
separate block-50000 witness sample, with URLs and digests. The replay verifies
network genesis before node submissions, checks three fixture mutations, rejects
an out-of-order block and a corrupted transaction Merkle root, accepts the
original prefix, and checks tip persistence across restart. Each child must exit
cleanly. The research workflow retains the native receipt alongside the exact
source archive and executable.

This is a bounded compatibility replay, not a public-network synchronization or
an activation of TXCOMMIT or CAT. No synthetic outputs or spends are broadcast
to Testnet4. Novel consensus spends remain in isolated patched regtest. The
block-50000 sample does not establish the intervening chain. Fixture acquisition
and scope are recorded in [the fixture provenance](../../scripts/tests/data/keyless-testnet4/README.md).

## Sources

- [Pinned Spiral proposal](https://github.com/patrickdugan/Spiral/blob/cfafbec4ae072b859f0140b2487baac14fac3a44/BIPSpace/Keyless-CHECKSIG/bip-keyless-checksig.md)
- [BIP341 signature message](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP342 signature opcodes and unknown key types](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [BIP347 CAT proposal](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki)
- [Synchronization contract](../contracts/synchronization.md)
