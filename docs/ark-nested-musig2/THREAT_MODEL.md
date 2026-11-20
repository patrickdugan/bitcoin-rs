# Ark with NestedMuSig2: threat model

## Parties and assets

| Party | Holds | Can do alone |
| --- | --- | --- |
| User | one key per role, boarding outputs, VTXOs, the signed exit tree for its VTXOs | spend a VTXO or boarding output through its CSV exit leaf after the delay |
| Operator (ASP) | operator key, liquidity outputs, connectors | sweep a tree node output after the batch expiry; spend connectors and its wallet |
| Coordinator | no keys; relays nonces, contexts and partial signatures | reorder, drop, substitute or replay messages |
| Signer process | one user's key, in-memory nonces | sign only targets that its validated statement allows |

The coordinator is untrusted. In this implementation the operator runs it, but
nothing in a signer's checks depends on the coordinator's honesty.

## Security goals

1. A user can always leave without the operator: it keeps a fully signed tree
   branch and its own exit key, and the exit leaf needs no other signature.
2. A user never gives up value (a boarding output or an old VTXO) before it
   holds a verified, fully signed exit path for what it receives in exchange.
3. A forfeit is spendable only if the round that replaced the VTXO confirmed:
   it spends a connector that exists only in that round's commitment.
4. A signature produced for one statement, tree node or network cannot
   authorize another, and no nonce signs twice.
5. A proof never makes an otherwise invalid Bitcoin spend acceptable.

## Assumptions

- Users come online at least once per batch expiry window. After the expiry
  the operator can sweep any tree node output that is still unspent. That is
  Ark's liveness assumption; the regtest scenario shows the sweep winning
  against a late exit.
- The exit tree must confirm before the operator's sweep timer runs out at
  every level. With relative timelocks each node output restarts its timer when
  the parent confirms.
- Fees: every tree and exit transaction carries a fixed fee chosen at signing
  time. Nobody can fee-bump it: the user cannot spend a VTXO before its CSV
  delay, and the tree has no anchor outputs. In a fee spike a user's exit can
  wait. Arkade's answer is TRUC transactions with P2A anchors and package
  relay; bitcoin-rs rejects the anchor spend under its standard flags today
  (see RESULTS.md).
- Funding observations come from nodes the participant trusts. On regtest the
  harness requires bitcoin-rs and Core to agree; on testnet4 the runner can
  take two nodes.

## Attack matrix

Every case has a single expected rejection stage. "Executed against" lists the
components that actually ran.

| Attack | Expected stage | Executed against |
| --- | --- | --- |
| Boarding funding output with a different script, as in the 2026 Bark board bug (the funding output paid the user's own key) | `funding-observed-script` | statement fixture, UTXOs observed on both nodes |
| Boarding funding output with a different value | `funding-observed-value` | same |
| Boarding funding output only in the mempool | `funding-observed-unconfirmed` | same |
| Batch output pays the operator's key instead of the cosigner aggregate | `batch-output-script` (native checker); the theft path is a valid bitcoin-rs-script spend | statement fixture, bitcoin-rs-script |
| Batch output smaller than the tree it funds | `value-conservation` | statement fixture |
| Operator shows two clients different trees for one commitment (equivocation) | `client-vtxo-amount`; both roots spend the same batch outpoint, so at most one can confirm | in-process signers |
| A participant omitted while its boarding input is spent | `client-vtxo-missing` | in-process signers |
| Participants reordered across subgroups | nested aggregate key and statement digest change; flat key does not | key derivation |
| Cooperative-exit address changed before the user signs | `client-coop-exit` | in-process signers |
| Cooperative-exit address changed after signing | `script-verification` | bitcoin-rs-script, bitcoin-rs node, Core |
| Same old VTXO forfeited twice | `forfeit-binding` | statement fixture |
| Forfeit broadcast before its round commits | `missing-inputs` | bitcoin-rs node, Core |
| Replayed forfeit after it confirmed | `already-spent` | bitcoin-rs node, Core |
| Unilateral exit of a VTXO already forfeited and claimed | `missing-inputs` | bitcoin-rs node, Core |
| Forged partial signature from one leaf | `partial-verify` | in-process and process signers |
| One leaf sent a different root aggregate nonce | `partial-verify` | same |
| Second partial signature for one session | `client-nonce-unavailable` | same |
| Nonce requested for a used session identifier | `client-session-reuse` | in-process signers |
| Nonce requested for an aggregate key other than the policy's | `client-aggregate-key` | in-process signers |
| Signer process killed after releasing a nonce, then asked to sign | `client-nonce-unavailable` | process signers |
| Boarding or forfeit signature requested before the signed tree is held | `client-tree-unsigned` | in-process signers |
| Premature unilateral exit, boarding recovery or operator sweep | `relative-locktime` | bitcoin-rs node, Core |
| Operator double-spends its liquidity under a pending commitment with too little fee | `replacement-fee` | bitcoin-rs node, Core |
| Same, with enough fee: the commitment is evicted and boarding outputs stay with their owners | accepted replacement; boarding outputs unspent | bitcoin-rs node, Core |
| Late exit competing with the operator's sweep, then a one-block reorganization | the sweep wins in the new chain; the tree root is rejected as `missing-inputs` | bitcoin-rs node, Core |
| Transaction with no fee reserve | `min-relay-fee` | bitcoin-rs node, Core |
| Proof for another statement, another network, altered public inputs, unknown schema, unpinned verifier key, truncated transcript or truncated proof | `statement-digest`, `network`, `public-inputs`, `unrecognized-schema`, `verifier-key`, `incomplete-transcript`, `nova-verifier` | `ark-nm2 verify-proof`, `ark-nova` |
| Valid proof attached to a statement whose tree signature was altered | proof accepted; native `script-verification` rejects; the settlement verdict needs both | `ark-nova`, bitcoin-rs-script |

## Open obligations

These are known gaps. None is covered by a test that claims otherwise.

- Nested security: the BIP draft's nested security argument is stated for
  depth two in the cited paper; the tree here reaches depth eight at 256
  users. The construction relies on that argument, which has no review at
  that depth.
- The X-only intermediate nonce-binding hash (`NestedMuSig/aggnoncecoef`) follows
  the draft's current text and the conformance follow-up pinned in
  `tools/nested-musig2`; the draft text has changed before.
- Restored-state nonce reuse is excluded only because nonces never touch
  disk. A virtual machine snapshot of a running signer process would restore
  live nonces; nothing here detects that.
- No transport authentication: the coordinator and signers speak over local
  pipes. A real deployment needs authenticated channels and a durable
  session-identifier store.
- The operator's per-round ephemeral signing key, connector trees, off-chain
  transfers and TRUC/P2A fee bumping are not implemented.
- Exit fees are fixed at signing time and cannot be bumped (see Assumptions).
