# BIP 448 on regtest

bitcoin-rs implements the BIP 448 package (BIP 446 `OP_TEMPLATEHASH`, BIP 348
`OP_CHECKSIGFROMSTACK`, BIP 349 `OP_INTERNALKEY`) behind a regtest-only switch.
Mainnet, testnet3, testnet4 and signet are unchanged: the three bytes stay
`OP_SUCCESS` there.

Spec text and vectors come from `bitcoin/bips` at commit
`b34d9f751791d4feb22feff4f2ed00bcac83961b` (the commit Spiral pins).

## What is implemented

| Opcode | Byte | Replaces | Behaviour |
| --- | --- | --- | --- |
| `OP_INTERNALKEY` | `0xcb` | `OP_SUCCESS203` | pushes the 32-byte taproot internal key from the control block |
| `OP_CHECKSIGFROMSTACK` | `0xcc` | `OP_SUCCESS204` | pops pubkey, message, signature; BIP 340 verify over the raw message; pushes `0x01`, or an empty vector for an empty signature |
| `OP_TEMPLATEHASH` | `0xce` | `OP_SUCCESS206` | pushes `TaggedHash("TemplateHash", nVersion, nLockTime, sha_sequences, sha_outputs, annex_present, input_index [, sha_annex])` |

Tapscript (leaf version `0xc0`) only. In legacy and witness-v0 scripts the
bytes stay invalid opcodes.

CSFS details: fewer than 3 stack items fails; an empty pubkey fails; a 32-byte
pubkey with a non-empty signature must verify as a 64-byte BIP 340 signature
(any other length fails with `SCHNORR_SIG_SIZE`, no sighash byte); any other
pubkey length is an unknown key type and succeeds. Each non-empty signature
spends 50 units of the BIP 342 sigops budget.

Code:

* `crates/script/src/bip448.rs`: opcode bytes, the activation switch, a
  safe-Rust BIP 340 verifier for messages of any length (the `secp256k1` 0.29
  API signs and verifies 32-byte messages only).
* `crates/script/src/eval.rs`, `checker.rs`, `interpreter.rs`: opcode
  execution, `VerifyFlags::BIP448` (bit 21; the BIP 446 vectors call it
  `TEMPLATEHASH`, both names parse), internal key taken from the control block.
* `crates/primitives/src/sighash.rs`: `SighashCache::template_hash`.
* `crates/consensus/src/bip448.rs`: `activate_bip448(network)`, which refuses
  anything but regtest.

## Activation switch

`bitcoin-rs --network regtest --bip448` (default off). The flag makes the
process evaluate every tapscript with `VerifyFlags::BIP448`, in block
validation and in mempool admission alike, so `DISCOURAGE_OP_SUCCESS` no longer
rejects these spends. On any other network the flag aborts startup with
`BIP 448 activation is limited to regtest`.

This was chosen over a CLI option threaded through `UserConfig`/`NodeConfig`
(many struct literals) and over an always-on regtest deployment (changes
regtest behaviour for existing OP_SUCCESS tests). The switch is process-wide
state set once at start-up, before any script is evaluated.

Without the flag the opcodes behave exactly as before. Existing script
vectors (34 lib and 64 suite tests in `bitcoin-rs-script`) pass unchanged.

## Tests

Run from a WSL-native checkout (Windows checkouts fail on symlinks):

```
cargo test -p bitcoin-rs-script                      # lib + suite, includes BIP vectors
cargo test -p bitcoin-rs-script --test suite bip448  # BIP 448 tests only
cargo test -p bitcoin-rs-consensus --lib bip448      # regtest-only activation
cargo test -p bitcoin-rs --test suite bip448_regtest -- --nocapture --test-threads=1
```

* `crates/script/tests/bip448.rs`: opcode bytes; flag off keeps OP_SUCCESS
  (consensus accepts, `STANDARD` rejects with `DISCOURAGE_OP_SUCCESS`); flag on
  is real; INTERNALKEY follows the output's internal key; TEMPLATEHASH against
  an independent implementation of the BIP preimage, each committed field,
  input index, annex, outpoint not committed; CSFS valid, wrong
  signature/message/key, wrong signature length, empty signature, empty and
  unknown pubkey sizes, stack underflow, sigops budget; the full
  `TEMPLATEHASH INTERNALKEY CSFS` rebindable leaf.
* BIP vectors: `bip446-basics.json` and `bip446-script_assets_test.json`
  (BIP 446), `bip340-test-vectors.csv` (BIP 340, including message lengths 0,
  1, 17, 32 and 100), run both directly against the verifier and through CSFS.
  BIP 348 and 349 publish no vectors.
* `bin/bitcoin-rs/tests/bip448_regtest_e2e.rs`: the demo below.

## End-to-end: 3-party LN-Symmetry-style channel

The channel key is a 3-party MuSig2 aggregate (the in-tree
`tools/nested-musig2` crate, flat 3-of-3) used as the taproot internal key.
Each state `n` is an output `TR(K, {update(n), settle(n)})`:

* `update(n)`: `<BASE+n+1> CLTV DROP TEMPLATEHASH INTERNALKEY CHECKSIGFROMSTACK`
* `settle(n)`: `<10> CSV DROP TEMPLATEHASH <template hash of settlement n> EQUAL`

State numbers ride in nLockTime (`BASE = 500,000,000`). An update transaction
is signed once by the aggregate over its own template hash and spends any
earlier state's output, because the template excludes the spent outpoint.

Flow, all on a bitcoin-rs regtest node started with `--bip448`, mined with
`generateblock` from the mempool:

1. A coinbase funds the state-0 output.
2. Update 1 (pre-signed) spends the funding output.
3. Update 2 previews as acceptable over state 1 (state skipping is allowed),
   but is never broadcast.
4. Update 3, signed once, spends the state-1 output. No penalty data exists.
5. Rejected: update 3 with its output value changed by 1 sat (also refused by
   consensus in `generateblock`), update 3 with a flipped signature bit, update
   3 carrying the state-2 signature, update 2 over the state-3 output (CLTV
   requires a higher state), a state-1 settlement against the state-3 output.
6. The state-3 settlement is refused (`non-BIP68-final`) until the output is 10
   blocks deep, then accepted and mined; it pays three outputs.

A second test starts a node without `--bip448`: a garbage-signature update is
refused by the mempool (`DISCOURAGE_OP_SUCCESS` policy) yet accepted by
consensus in a block, the OP_SUCCESS behaviour.

Regtest enforces CSV (BIP 68/112) from height 432, so the test mines past it
first.

### Measured sizes

| Transaction | vsize (vB) | weight (WU) | witness (B) |
| --- | --- | --- | --- |
| funding (P2PKH coinbase to P2TR) | 201 | 804 | n/a |
| update, state 1 (spends funding) | 131 | 521 | 143 |
| update, state 3 (spends state 1) | 131 | 521 | 143 |
| settlement, state 3 (3 outputs, CSV) | 171 | 684 | 106 |

An update is 131 vB for any number of parties: the 3-party signature is one
64-byte BIP 340 signature. The node's `getmempoolentry` vsize matched the
library value for every broadcast transaction.

## Not covered

* Fee handling: update outputs shrink by a fixed fee per state; there is no
  anchor or fee-bumping input, and spending an older state with a newer update
  donates the difference to fees.
* The `kernel` validation engine (libbitcoinkernel) does not know these
  opcodes; run with the default native engine.
* No BIP 448 deployment parameters (BIP 9, height) for any network.
* The CSFS unknown-pubkey-type policy reuses `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`
  from BIP 342 checksig; BIP 348 does not state a policy rule.
* No LN-Symmetry wire protocol, MuSig2 nonce persistence or watchtower logic.
