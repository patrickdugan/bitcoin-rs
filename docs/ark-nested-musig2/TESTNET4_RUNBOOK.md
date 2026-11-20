# Testnet4 runbook

This guide runs the Ark lifecycle against public testnet4 with small,
disposable coins. Nothing is broadcast unless you add `--broadcast` to a
command. Run each stage, read its `receipt.json`, then decide.

## What you need

- A fully synchronized testnet4 node with RPC on a loopback address and a
  cookie file: bitcoin-rs (`--network testnet4`) or Bitcoin Core. A second
  node is optional; with one node the runner records a single observer.
- The `ark-nm2` binary from the CI artifact `ark-tool-*`, or
  `cargo build --locked --profile quickstart -p bitcoin-rs-ark-nested-musig2`.
- About 0.006 tBTC in one confirmed output.

Keys and RPC credentials stay on your machine. The runner writes only public
data into its output directory. Do not upload the key directory anywhere.

## 1. Create keys

```sh
install -d -m 700 target/ark-testnet4/keys
target/quickstart/ark-nm2 init --dir target/ark-testnet4/keys --users 5 --network testnet4 \
  > target/ark-testnet4/public-keys.json
```

`init` writes seven key files with mode 0600 (faucet, operator, five users)
and refuses to overwrite existing ones. `public-keys.json` holds the faucet
address.

## 2. Preflight

```sh
python3 scripts/run-ark-nested-musig2-testnet4.py --stage preflight \
  --ark target/quickstart/ark-nm2 --keys target/ark-testnet4/keys \
  --rpc-url http://127.0.0.1:48332 --cookie ~/.bitcoin/testnet4/.cookie \
  --output target/ark-testnet4/preflight
```

The preflight checks that the chain is `testnet4`, that block 0 is
`00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043`, that the
node has left initial block download, that headers equal blocks, and that
verification progress is at least 0.9999.

## 3. Fund

Send about 0.006 tBTC to the faucet address and wait for one confirmation.
Then preview the funding transaction:

```sh
python3 scripts/run-ark-nested-musig2-testnet4.py --stage fund \
  --ark target/quickstart/ark-nm2 --keys target/ark-testnet4/keys \
  --rpc-url http://127.0.0.1:48332 --cookie ~/.bitcoin/testnet4/.cookie \
  --faucet-outpoint TXID:VOUT --faucet-sat AMOUNT \
  --output target/ark-testnet4/fund-preview
```

The runner checks that the outpoint exists, is confirmed, pays the faucet key
and has the stated value. It builds a transaction with five boarding outputs
(20,000 to 24,000 sat), three operator liquidity outputs (100,000 sat each),
two 20,000 sat outputs for the anchor package probe and change. It refuses if
more than `--max-total-sat` (600,000) would leave the faucet, and stops if the
node's `testmempoolaccept` rejects it. Read `funding.json`. To broadcast,
repeat the command with a new `--output` directory and `--broadcast`, then
wait for one confirmation.

## 4. Round

```sh
python3 scripts/run-ark-nested-musig2-testnet4.py --stage round \
  --ark target/quickstart/ark-nm2 --keys target/ark-testnet4/keys \
  --rpc-url http://127.0.0.1:48332 --cookie ~/.bitcoin/testnet4/.cookie \
  --funding target/ark-testnet4/fund-broadcast/funding.json \
  --output target/ark-testnet4/round-preview
```

This stage observes every funding output on the node, runs the full scenario
(rounds 0 to 2, two signer processes, all adversarial cases), and previews
without broadcasting:

- the round 1 commitment alone (`cooperative_preview`);
- the commitment with the whole tree as one package (`tree_package_preview`);
- each user's recovery package: commitment, tree and exit. The exit must fail
  only on its relative timelock (`exit_blocked_only_by_relative_locktime`).

`--broadcast` sends only the round 1 commitment, and only after the node
accepted the preview. Exits, forfeits and sweeps stay unbroadcast; their raw
transactions are in `scenario/scenario.json`. Exit delays are in blocks (12
for VTXOs, 30 for boarding outputs, 40 for the batch expiry).

## If something is missing

- No synchronized node: the preflight fails and writes its checks to
  `receipt.json`.
- No funds: the fund stage stops at the outpoint check.
- Funding unconfirmed: the round stage stops with "confirm the funding first".
