# NestedMuSig2 conformance fixtures

`conformance.json` holds public test secrets and deterministic nonces. These
values serve only as fixtures. The staging command creates fresh random keys.

The generator imports two independent Python references. It checks their SHA256
before execution:

| Reference | Revision | SHA256 |
| --- | --- | --- |
| [NestedMuSig2 corrected reference](https://github.com/patrickdugan/bips/blob/44e9d2518e7fa9073fd904f6224b221057c48c2c/bip-nested-musig2/reference.py) | `44e9d2518e7fa9073fd904f6224b221057c48c2c` | `e22d98df42838a3ac9106df0c6e96b3ee3242a5a081aee54ae183aa0b282d2ef` |
| [BIP327 reference](https://github.com/bitcoin/bips/blob/9cf75150d27c4e735ddde933a92d00bf083a18d4/bip-0327/reference.py) | `9cf75150d27c4e735ddde933a92d00bf083a18d4` | `1167993fe159c39c004f74d9046e931ae700a2ce9203c4cf58a51a000c1294e8` |

The NestedMuSig2 reference follows the nonce-first X-only binding from draft
revision `4523ee0eed72f2367a1d1774941f70b2aca5af43` and applies the conformance
corrections from [author PR 2](https://github.com/BEULAHEVANJALIN/bips/pull/2).
Its BIP327-derived helpers and the BIP327 reference carry the source project's
BSD-2-Clause terms. The fixture generator calls those sources; it does not copy
their implementation into this repository.

## Coverage

Nine flat sessions compare each nonce, partial signature and final signature
with BIP327. Five nested sessions cover balanced and mixed-depth trees, repeated
key occurrences and a depth-three path. Messages have lengths 0, 1, 17, 32, 33
and 100 bytes. Root tweaks include ordinary and X-only modes in mixed order.
Four BIP327 nonce generation cases also cover absent optional fields, an empty
message and a message longer than 32 bytes.

The fixture records each node's internal nonce, external nonce and summed
partial. Tests reverse each node's input keys to check mandatory sorting, and
preserve each repeated key occurrence. A point and its negation must produce
the same intermediate nonce coefficient because that hash uses X-only bytes.

The root parity case uses secret scalar 3 and ordinary tweak 3. Its final key
has odd parity while `gacc` is positive. The fixture includes a signature made
with the wrong `c * gacc * tacc` correction. Independent libsecp256k1 verification
rejects that signature and accepts the one formed with `c * g * tacc`.

Other tests check malformed lengths, invalid scalar ranges, public nonce
cancellation, finite-generator acceptance, resource bounds, changed messages,
changed root keys and malformed paths. The core's compile-fail doctest checks
that a nonce cannot be passed to signing twice. Secret nonce memory handling
also needs code review; a compiler ownership check does not prove erasure from
all machine copies.

## Reproduce

Retrieve the two files at the revisions linked above, then run:

```sh
python3 tools/nested-musig2/tests/fixtures/generate.py \
  --nested-reference /path/to/nested-reference.py \
  --bip327-reference /path/to/bip327-reference.py
cargo test --locked -p bitcoin-rs-nested-musig2 --features conformance
```

The generator checks every final signature with the Python BIP340 verifier.
Rust tests compare complete bytes with the fixture. They also pass every
32-byte-message signature to libsecp256k1's independent Schnorr verifier.
Normal CI uses the committed JSON and needs no network access to a BIP branch.

These checks establish conformance for the listed cases. General-depth protocol
security and the proof's fit to the selected hash encoding remain research
questions. The transaction staging profile uses two levels.
