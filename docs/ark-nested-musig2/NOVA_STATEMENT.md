# ArkTransitionV1 and the Nova relation

## Canonical statement

`ArkTransitionV1` is the one byte format for a round. The operator builds it,
every cosigner validates it before signing, the native checker re-derives
every rule from it, and the Nova witness is a pure function of it.

Integers are little-endian. `count` is a `u16` at most 4096. `var` is a `u32`
length followed by at most 400,000 bytes. Keys are 33-byte compressed points
and must parse. Transactions are serialized without witness data.

```
magic            "ARKTRNV1"                 8 bytes
version          u16 = 1
network          u8   (0 regtest, 1 testnet4)
genesis          32 bytes (block hash, internal byte order)
round            u32
sequence         u32  (state sequence of this operator's rounds)
previous         32 bytes (digest of the previous settled statement, or zero)
policy
  shape          u8   (1 nested, 2 flat)
  operator key   33 bytes
  exit delay     u16  blocks
  boarding delay u16  blocks
  batch expiry   u16  blocks
  fee rate       u64  sat per 1000 vB
  fee bound      u64  sat, the largest fee any transaction in the graph may pay
  connector      u64  sat per connector output
participants     count x (owner key 33, amount u64)               ordered VTXO leaves
funding          count x (outpoint 36, amount u64, script var, kind u8, owner key 33 if boarding)
old vtxos        count x (outpoint 36, amount u64, owner key 33, script var)
commitment       var  transaction template
batch vout       u32
connectors       count x vout u32
coop exits       count x (vout u32, owner key 33, amount u64, script var)
tree             count x (lo u16, hi u16, parent u16 or 0xffff, parent vout u32, transaction var)
forfeits         count x (old index u16, connector index u16, transaction var)
anchor           block hash 32, height u32, assumption u8 (0 unanchored, 1 funding observed confirmed by named nodes)
```

Decoding rejects unknown magic, version, network, shape, funding kind or
anchor codes; truncation; trailing bytes; a transaction that does not
re-serialize to the same bytes; any witness data; and any input that does not
re-encode to exactly the same bytes.

The digest is `SHA256(SHA256(tag) || SHA256(tag) || bytes)` with tag
`ArkTransitionV1/statement`. Because the digest covers the network, genesis,
round, policy keys and every transaction template, a signature or proof bound
to one digest cannot authorize another batch, network or output destination.
Every MuSig2 session identifier and every nonce's extra input carries a
prefix of this digest.

## What binds what

| Property | Bound by | Established by |
| --- | --- | --- |
| Network and genesis | digest | native checker compares with the network's genesis block |
| Funding outpoints, amounts and scripts | digest; the commitment's inputs must equal the funding list | `gettxout` on bitcoin-rs and Core at the anchor; the cosigners compare script, value and confirmations |
| Old and new VTXO commitments | digest (old VTXO list; participant list plus tree outputs) | native checker derives every VTXO script from owner, operator and exit delay |
| Participant keys, operator identity and signing policy | digest (policy and participant keys) | native checker recomputes every node's aggregate key and BIP341 output |
| Transaction templates, output amounts, fee bounds | digest | native checker: conservation and fee bound per transaction |
| Forfeit and connector commitments | digest | native checker: each forfeit spends a connector of this commitment and one old VTXO, each exactly once |
| Round identity, sequence, expiry, exit conditions | digest (round, sequence, previous, delays) | native checker |
| Chain anchor and its assumption | digest | the anchor records which nodes observed the funding; no SPV or header proof is included |
| Transaction validity | not in the statement | bitcoin-rs-script per input; bitcoin-rs and Core acceptance |
| Inclusion and canonical chain | not in the statement | block hashes reported by both nodes |
| UTXO non-spentness | not in the statement | `gettxout` at lookup time only |

A hash commitment by itself proves none of the properties in the last column.

## The Nova relation

The circuit lives in `zk-rusto-no-bitcoino`, branch `feat/ark-transition-nova`,
under `integrations/ark-transition-nova`. Its witness is exported by
`ark-nm2 nova-witness`:

- for each transaction in graph order (commitment, tree by index, forfeits by
  index): one `input` item per input with `spend_id` and value, one `output`
  item per output with value and `commit`, and one `close` item with the fee;
- `spend_id = TaggedHash("ArkTransitionV1/spend", txid || vout_le)`;
- `commit = TaggedHash("ArkTransitionV1/output", value_le || scriptPubKey)`.

One folding step consumes one item; after the graph, one step per input
consumes the spend identifiers in sorted order. The public state starts from
the statement digest, the fee bound and a Fiat-Shamir challenge `gamma`. The
relation proven:

1. for every transaction, the inputs equal the outputs plus the fee;
2. every fee is at most the statement's fee bound, and every value is below
   2^64;
3. the sorted spend identifiers are strictly increasing, so no spend repeats;
4. the sorted list is a permutation of the graph-order inputs: the grand
   products of `(gamma - spend)` over both lists are equal, where
   `gamma = Poseidon(r1, r2)` and `r1`, `r2` are the Poseidon chains over the
   two lists;
5. `r1` commits to the item list.

Identifiers are truncated to 248 bits to fit one field element, which leaves
124-bit collision resistance for the uniqueness check.

`ark-nm2 verify-proof` checks, before calling the verifier binary: the schema
names, the expected network, the statement digest, the fee bound, the pinned
verifier-key digest, and that the witness supplied equals the witness
recomputed from the statement (no truncated or reordered transcript). Then it
runs `ark-nova verify` and requires an accepted verdict for the same verifier
key.

## What the proof does not cover

- No signature, sighash or script execution is in the circuit. A valid proof
  for a statement whose tree signature is corrupt still verifies; the native
  script check rejects that transaction, and the settlement verdict requires
  both checks. `run-ark-nova-mode.py` runs exactly that control.
- The link from records to Bitcoin transactions is the native recomputation
  of the witness from the statement bytes, not a SHA-256 relation in the
  circuit.
- No inclusion, header chain or UTXO-set relation. The M18 windowed UTXO map
  can authenticate outputs created inside a proven block window under its
  assume-valid assumptions; it is not connected here and does not prove
  global unspentness.

## Script-level proving with M17

M17 (`integrations/bitvm3-nova/m17`) proves legacy, P2SH and witness v0 script
execution. Every spend in this Ark graph is Taproot: key-path spends of
aggregate keys and tapscript leaves with CHECKSIG, CHECKSIGVERIFY and CSV.
M17 covers none of them. The `taproot-provable` Shinigami branch
(`19cb9fab4664e8f7fc4936f018d9c59ccac5883c`) evaluates tapscript in Cairo,
but M17's step machine has no tapscript signature version, no BIP341 sighash,
no control-block check and no validation-weight budget. Its deferred
signature claims are BIP143 and legacy only. A Taproot extension needs those
four pieces plus a cross-check against Core's 2,239 Taproot vectors before any
Ark spend can be proven at script level. That work is not done; see
RESULTS.md for what this means for the comparison.

## SP1 and BitVM3

An SP1 or BitVM3 wrapper is gated on the Nova verifier accepting the same
statement and on its mutation controls failing. The M14 garbled verifier
checks SP1 Groth16 proofs, not Nova proofs of this circuit, so it has no
input to consume until such a wrapper exists. No wrapper was built.
