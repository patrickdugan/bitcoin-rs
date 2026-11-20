# arkade-interop

Standalone checker that derives Arkade default VTXO and boarding outputs with the real
`ark-core` crate from arkade-os/rust-sdk, so another Ark harness can be compared byte for byte.
It is its own Cargo workspace (not a member of the bitcoin-rs workspace) with its own `Cargo.lock`.

## What is compared

For each `(server_xonly, owner_xonly, exit_blocks)` case, using a blocks-type relative locktime
`Sequence::from_height(exit_blocks)`:

- `script_pubkey`: on-chain P2TR scriptPubKey of the default VTXO, `Vtxo::new_default(..).script_pubkey()`
  (rust-sdk `ark-core/src/vtxo.rs:175`). Internal key is the fixed NUMS point `UNSPENDABLE_KEY`.
- `tapscripts`: the two leaf scripts, `Vtxo::tapscripts()` (`vtxo.rs:260`), in order
  `[forfeit, exit]`:
  - forfeit: `<server> OP_CHECKSIGVERIFY <owner> OP_CHECKSIG` (server key first)
  - exit: `<exit_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP <owner> OP_CHECKSIG`
- `ark_address`: bech32m Ark address, `Vtxo::to_ark_address().encode()` (`vtxo.rs:199`, `ark_address.rs:50`);
  `tark` HRP on regtest.
- `boarding_script_pubkey`, `boarding_tapscripts`, `boarding_address`: `BoardingOutput::new(..)` with the same
  keys and delay (`boarding_output.rs:34`; `script_pubkey()`, `tapscripts()`, `address()`).

The pinned dependency is `ark-core` 0.12.1 from git rev `c786942969dd16f9e94fc165a99a329a39ed183d`
(package name `ark-core`, identical to the crates.io name). `bitcoin = 0.32.7` is a direct dependency
only for the key, script and network types in the `ark-core` signatures.

## Command line

Build and run inside WSL (the exact commands used):

```
cd /root/ark-interop            # rsync of this directory
CARGO_TARGET_DIR=/root/ark-interop/target cargo build --release -j 6
echo '{"network":"regtest","cases":[{"server_xonly":"79be667e...f81798","owner_xonly":"c6047f94...709ee5","exit_blocks":12}]}' \
  | /root/ark-interop/target/release/arkade-interop
```

Input: `{"network":"regtest","cases":[{"server_xonly":"<64hex>","owner_xonly":"<64hex>","exit_blocks":12}]}`
(`network` is one of `bitcoin`, `testnet`, `signet`, `regtest`; `exit_blocks` fits in u16).
Output: JSON with `schema` `arkade-interop-v1`, `ark_core_rev`, and one object per case.

## Observed output

Case: server = G (`79be667e...f81798`), owner = 2G (`c6047f94...709ee5`), `exit_blocks` = 12, regtest.
Full output is in `fixtures/g-2g-12.json`.

- `script_pubkey`: `5120df276373d95787ca03caa6b7f1d3be22d9470cde4b8dc693627e93dc588f4534`
- `tapscripts[0]` (forfeit): `2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad20c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac`
- `tapscripts[1]` (exit): `5cb27520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac`
- `ark_address`: `tark1qpumuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqte3he8vdeaj4u8egpu4f4h78fmugkeguxdujudc6fkyl5nm3vg73f5prs56w`
- `boarding_address`: `bcrt1pmunkxu7e27ru5q7256mlr5a7ytv5wrx7fwxudymz06facky0g56qr68zyc` (same script_pubkey as the VTXO, since the boarding delay equals the exit delay)
