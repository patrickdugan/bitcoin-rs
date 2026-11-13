# Public Testnet4 fixtures

These immutable public block bytes were acquired on 2026-11-13 from
`https://mempool.space/testnet4/api`, after checking its height-zero mapping
against Testnet4 genesis
`00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043`.
`report.json` records each requested hash, raw-block URL, length and SHA256.
Its `passed` status describes fixture verification, not a node execution.

Blocks 0 through 12 form a contiguous prefix. Block 50000 supplies a separate
SegWit transaction and witness-commitment sample; this fixture does not establish
the intervening header chain or replay the node through height 50000.

The harness independently recomputes header hashes, proof of work, transaction
Merkle roots and available BIP141 witness commitments. It rejects mutations of
the header, transaction body and witness. Node replay additionally rejects an
out-of-order block and a corrupted Merkle root, then accepts the original blocks
and verifies the persisted tip after a clean restart.

The larger acquisition stopped on HTTP 429 after block 12. The retained verified
bytes allow deterministic offline replay without further API requests.
