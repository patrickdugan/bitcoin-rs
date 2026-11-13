# Funded arithmetic-claim dispute

This fixture spends real regtest outputs through the experimental native
`OP_MULADDMOD` interpreter. It tests one canonical arithmetic claim fixed
before funding. All participant secrets are public test constants. Use a
fresh isolated regtest data directory. Never send funds to these scripts.

## Build and run

```sh
cargo build --locked --profile quickstart -p bitcoin-rs \
  --no-default-features --features fjall,experimental-muladdmod-regtest
python3 scripts/research/muladdmod_dispute_rpc.py target/quickstart/bitcoin-rs \
  --report dispute-small.json
python3 scripts/research/muladdmod_dispute_rpc.py target/quickstart/bitcoin-rs \
  --wide --report dispute-wide.json
python3 -m unittest discover -s scripts/tests -p 'test_muladdmod_claim.py' -v
```

The RPC fixture uses Python's standard library. It starts the node with the
native engine and Fjall storage, binds RPC and P2P to loopback, disables DNS
seeds, and removes its temporary data directory after shutdown. Python
assertions must be enabled. It writes a JSON receipt and the node log.
The receipt includes the executable digest and confirmed transaction IDs.

## Claim admission and script

Each admitted claim fixes a 32-byte instance identifier, the modulus, the
operands `a`, `b`, `c`, and the claimed residue `d`. The constructor requires
canonical residues, a modulus from 2 through 2^256-1, and a block delay from
1 through 65535. The recovery and operator public keys are fixed test keys.

A funder must reconstruct this complete script and inspect the committed
values before sending money. The constructor is an admission check. The
script cannot prove that an unknown hash preimage has a canonical encoding.
An application that admits malformed commitments needs a separate encoding
challenge; this fixture does not implement that branch.

The Taproot internal key is the reproducible NUMS point given in BIP 341.
The single leaf commits the complete claim. The instance identifier is
pushed and dropped so it changes the leaf hash and output key without
changing the arithmetic. A unique label alone does not prevent duplicate
funding of one economic claim.

The script has these branches:

```
<instance> DROP
IF
  <recovery_public_key> CHECKSIGVERIFY
  DUP SHA256 <H(d)> EQUALVERIFY TOALTSTACK
  DUP SHA256 <H(c)> EQUALVERIFY TOALTSTACK
  DUP SHA256 <H(b)> EQUALVERIFY TOALTSTACK
  DUP SHA256 <H(a)> EQUALVERIFY
  FROMALTSTACK FROMALTSTACK <modulus> OP_MULADDMOD
  FROMALTSTACK EQUAL NOT
ELSE
  <delay> CHECKSEQUENCEVERIFY DROP
  <operator_public_key> CHECKSIG
ENDIF
```

Recovery supplies `a b c d signature 01` before the leaf and control block.
After checking the signature, the script checks each preimage at its
assigned stack position. It computes `(a*b+c) mod m` and requires that
result to differ from `d`. All hash comparisons and arithmetic execute in
Script on the node.

Settlement supplies `operator_signature empty`. The spend uses version 2
and a block-based sequence equal to the delay. Both branches consume the
same claim output. Once either spend confirms in the retained chain, the
other lacks an unspent input.

The fixture uses BIP 340 signatures and the BIP 341 default hash type. The
signature commits all outputs and the input's outpoint, amount, script and
sequence, together with the tapscript extension. A copied authorization
fails on another instance or a redirected output. The authorized beneficiary
can sign a different destination. This fixture has no output covenant.
Recovery requires that beneficiary's participation.

## Live sequence

The harness mines to height 432 before funding. This fork activates its
CSV rules at that regtest height. Testing delayed settlement below that
height would exercise a different rule set.

A funding transaction creates three 100,000-sat claim outputs at height
433. One contains a false result and receives a timely challenge. A second
contains the correct result. The remaining false claim demonstrates a
missed challenge window. Each terminal spend pays a 2,000-sat fixture fee.

For the small-field run, the correct calculation is `(7*11+3) mod 17 = 12`.
The false claims commit 13. The wide run uses `m=2^255-19`, with
`a=b=c=m-1`: the correct residue is zero and the false claims commit one.

The node rejects substituted operands, a changed result, an invalid width,
and unauthorized signatures. The small-field run also swaps the unequal
`a` and `b` operands; the wide run has equal operands and omits that case.
A changed modulus script fails against the funded Taproot commitment.
The harness also tests a copied signature across instances, copied leaf
and control data, a changed recipient, an empty signature, and a
nonminimal branch selector.

An attempted recovery of the honest claim fails through both mempool RPCs
and direct block generation. Rejection leaves the chain height unchanged.
Premature settlement fails before the six-block delay. A newly signed
settlement with the sequence-disable bit set also fails, so its signature
cannot bypass `CHECKSEQUENCEVERIFY`.

The valid recovery confirms at height 434 and pays 98,000 sats to the
recovery beneficiary. The honest claim settles at height 439. The node
restarts and the fixture checks the consumed inputs and retained outputs.

At that point the third false claim has reached maturity. Both its correct
recovery and its delayed settlement are individually eligible. The harness
chooses settlement and mines it at height 440. A later valid challenge
fails because the claim output has already been consumed. The receipt
records this expected failure mode under `missed_window`.

The final test expects 19 rejection cases for the small field and 18 for
the wide field. The workflow runs both fixtures against its freshly built
executable. Local receipts and CI receipts identify their own binaries.

## Evidence and boundaries

The offline suite checks the test signer against official BIP 340 signing
vectors 0 and 1. It also checks canonical admission, context binding,
fixed-width values and the default signature-hash commitments. Real node
acceptance checks the independent transaction and signature serialization.

This is a fixed one-step claim contract. It has no committee presigning or
key-erasure ceremony. It still requires live participant signatures and
honest admission of the fixed statement. It does not implement a general
BitVM trace compiler, a SNARK/STARK verifier, cross-claim uniqueness or
watchtower service. It leaves evidence availability and timely transaction
inclusion to the application.

The NUMS construction rules out a known internal signing key under the
usual discrete-log assumption. The complete single-leaf tree remains part
of the funder's inspection. This property does not authenticate another
program or prove a separate garbling ceremony correct.

The six-block delay and fee are test constants. Deployments need measured
challenge capacity, fee management and a conservative reorganization
margin. The opcode's 50-unit charge remains provisional. This fixture
changes no public-network activation rules.

## References

- [BIP 340 and official vectors](https://github.com/bitcoin/bips/tree/master/bip-0340)
- [BIP 341: signature message and NUMS internal key](https://bips.dev/341/)
- [BIP 342: tapscript](https://bips.dev/342/)
- [BIP 68: relative sequence locks](https://bips.dev/68/)
- [BIP 112: CHECKSEQUENCEVERIFY](https://bips.dev/112/)
- [Opcode integration and synchronization scope](muladdmod.md)
