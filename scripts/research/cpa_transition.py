"""Bounded CPA disclosed-NAND delegation on isolated TXCOMMIT/CAT regtest.

The compiler checks every reachable gate and retains the parent's payout cap.
Both public outputs of the circuit are interpreted as (permission, selector).
The witness is public. This profile provides no zero knowledge or singleton.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct

import canonical_proof_authority as cpa
import keyless_checksig_rpc as base
from keyless_state_machine import _Builder


MAX_NODES = 32
MAX_INPUTS = 8
FEE = 2_000
ROOT_AMOUNT = 100_000
ROOT_CAP = 8_000
NODES = {'a': ('input', 0), 'b': ('input', 1), 'select': ('input', 2),
         'n': ('nand', 'a', 'b'), 'permit': ('nand', 'n', 'n')}
OUTPUTS = ('permit', 'select')
FIELDS = ('state_opening', 'parent_id', 'current_state', 'grant_id', 'public_digest',
          'child_statement', 'outpoint', 'spent_key', 'tapleaf')
DROP, VERIFY, EQUALVERIFY = 0x75, 0x69, 0x88
SHA256, ADD, NUMEQUAL, NUMEQUALVERIFY, LTE = 0xa8, 0x93, 0x9c, 0x9d, 0xa1
TOALT, FROMALT = 0x6b, 0x6c


def identity(label: str) -> bytes:
    return cpa.tagged_hash('CPA/v0/Profile', label.encode('ascii'))


NETWORK = identity('bitcoin-regtest-only')
PROFILE = identity('nums-p2tr-two-leaf-kcs2-cat-single-input-v0')
SUITE = identity('disclosed-nand-dag-direct-script-v0')
ABI = identity('permission-selector-state44-child-statement128-v0')
DELEGATION = identity('in-place-epoch-grant-retained-payout-cap-v0')
RESOURCES = identity('max32nodes-max8inputs-max2outputs-no-recursion-v0')


@dataclass(frozen=True)
class Leaf:
    script: bytes

    def output(self) -> tuple[bytes, bytes]:
        sibling = base.tapleaf(b'\x6a')
        root = cpa.tapbranch(base.tapleaf(self.script), sibling)
        key, parity = base.tweaked_key(base.NUMS_X, root)
        return b'\x51\x20' + key, bytes([0xc0 | parity]) + base.NUMS_X + sibling


@dataclass(frozen=True)
class Action:
    payout: int
    recipient: int
    successor: Stage | None


@dataclass(frozen=True)
class Stage:
    descriptor: cpa.Descriptor
    program: cpa.Program
    amount: int
    epoch: int
    cap: int
    grant: bytes
    state: bytes
    body: bytes
    leaf: Leaf
    actions: tuple[Action, Action]

    @property
    def authority(self) -> bytes:
        return self.descriptor.authority_id()

    @property
    def state_root(self) -> bytes:
        return cpa.state_root(self.state)


def statement(authority: bytes, state: bytes, grant: bytes, digest: bytes) -> bytes:
    return cpa.tagged_hash('CPA/v0/ChildStatement', b''.join(
        cpa.hash32(item) for item in (authority, state, grant, digest)))


def trace(program: cpa.Program, inputs: tuple[int, ...]) -> tuple[int, ...]:
    base.require(all(type(bit) is int and bit in (0, 1) for bit in inputs), 'invalid input bit')
    values = {}
    for node_hash, record in program.records:
        if record[0] == 0:
            index = int.from_bytes(record[1:], 'little')
            base.require(index < len(inputs), 'missing input')
            value = inputs[index]
        elif record[0] == 1:
            value = record[1]
        else:
            value = 1 - values[record[1:33]] * values[record[33:65]]
        values[node_hash] = value
    return tuple(values[node_hash] for node_hash, _ in program.records)


def terminal(program: cpa.Program, epoch: int, selector: int) -> bytes:
    return cpa.tagged_hash('CPA/v0/Terminal', program.program_id +
                           struct.pack('<I', epoch) + bytes([selector]))


def outputs_for(program: cpa.Program, epoch: int, selector: int,
                action: Action) -> tuple[base.Output, base.Output]:
    payout = base.Output(action.payout, b'\x51\x20' + base.RECIPIENTS[action.recipient])
    if action.successor is None:
        return payout, base.Output(0, b'\x6a\x20' + terminal(program, epoch, selector))
    return payout, base.Output(action.successor.amount, action.successor.leaf.output()[0])


def witness_fields(program: cpa.Program) -> tuple[str, ...]:
    return FIELDS + tuple('gate_' + node_hash.hex() for node_hash, _ in program.records)


def _bit(builder: _Builder, name: str):
    builder.pick(name)
    builder.number(0)
    builder.op(NUMEQUAL, 2, '')

    def zero(b):
        b.width(name, 0)

    def one(b):
        b.pick(name)
        b.const(b'\x01')
        b.op(EQUALVERIFY, 2)

    builder.conditional(zero, one)


def _check_program(builder: _Builder, program: cpa.Program):
    for node_hash, record in program.records:
        name = 'gate_' + node_hash.hex()
        _bit(builder, name)
        if record[0] == 1:
            builder.pick(name)
            builder.number(record[1])
            builder.op(NUMEQUALVERIFY, 2)
        elif record[0] == 2:
            builder.pick('gate_' + record[1:33].hex())
            builder.pick('gate_' + record[33:65].hex())
            builder.op(ADD, 2, '')
            builder.number(2)
            builder.op(NUMEQUAL, 2, '')
            builder.number(0)
            builder.op(NUMEQUAL, 2, '')
            builder.pick(name)
            builder.op(NUMEQUALVERIFY, 2)
    builder.pick('gate_' + program.output_hashes[0].hex())
    builder.number(1)
    builder.op(NUMEQUALVERIFY, 2)


def _action(builder: _Builder, program: cpa.Program, epoch: int,
            cap: int, selector: int, action: Action):
    builder.number(action.payout)
    builder.number(cap)
    builder.op(LTE, 2, '')
    builder.op(VERIFY, 1)
    outputs = outputs_for(program, epoch, selector, action)
    builder.const(outputs[0].serialize())
    builder.const(outputs[1].serialize())
    builder.cat()
    builder.op(SHA256, 1, 'outputs_hash')


def _body(program: cpa.Program, amount: int, epoch: int, cap: int,
          grant: bytes, state: bytes, actions: tuple[Action, Action]) -> bytes:
    builder = _Builder(witness_fields(program) + ('A', 's'))
    for field, width in ((name, 44 if name == 'state_opening' else 36 if name == 'outpoint' else 32)
                         for name in FIELDS):
        builder.width(field, width)
    for claim, locked in (('parent_id', 'A'), ('current_state', 's')):
        builder.pick(claim)
        builder.pick(locked)
        builder.op(EQUALVERIFY, 2)
    builder.pick('state_opening')
    builder.const(state)
    builder.op(EQUALVERIFY, 2)
    builder.pick('state_opening')
    builder.tag('CPA/v0/State', '')
    builder.pick('s')
    builder.op(EQUALVERIFY, 2)
    builder.pick('grant_id')
    builder.const(grant)
    builder.op(EQUALVERIFY, 2)
    _check_program(builder, program)
    builder.pick('gate_' + program.output_hashes[1].hex())
    builder.conditional(lambda b: _action(b, program, epoch, cap, 1, actions[1]),
                        lambda b: _action(b, program, epoch, cap, 0, actions[0]))
    builder.const(b'\x00\x00' + struct.pack('<iI', 2, 0))
    builder.pick('outpoint')
    builder.op(SHA256, 1, '')
    builder.cat()
    builder.const(base.sha(struct.pack('<Q', amount)))
    builder.cat()
    builder.const(b'\x22\x51\x20')
    builder.pick('spent_key')
    builder.cat()
    builder.op(SHA256, 1, '')
    builder.cat()
    builder.const(base.sha(struct.pack('<I', 0xfffffffd)))
    builder.cat()
    builder.pick('outputs_hash')
    builder.cat()
    builder.const(b'\x02' + bytes(4))
    builder.cat()
    builder.pick('tapleaf')
    builder.cat()
    builder.const(b'\x02\xff\xff\xff\xff')
    builder.cat()
    builder.tag('TapSighash', 'digest')
    builder.pick('digest')
    builder.pick('public_digest')
    builder.op(EQUALVERIFY, 2)
    builder.pick('A')
    builder.pick('s')
    builder.cat()
    builder.pick('grant_id')
    builder.cat()
    builder.pick('digest')
    builder.cat()
    builder.tag('CPA/v0/ChildStatement', '')
    builder.pick('child_statement')
    builder.op(EQUALVERIFY, 2)
    builder.op(TOALT, 1)
    while builder.stack:
        builder.op(DROP, 1)
    builder.op(FROMALT, 0, 'digest')
    base.require(builder.stack == ['digest'], 'invalid verifier stack')
    return bytes(builder.code)


def _stage(program: cpa.Program, amount: int, epoch: int, cap: int,
           actions: tuple[Action, Action]) -> Stage:
    for value in (amount, cap):
        base.require(type(value) is int and 0 <= value < 2**31, 'profile amount outside ScriptNum range')
    cpa.u32(epoch)
    scope = b''.join(output.serialize() for selector, action in enumerate(actions)
                     for output in outputs_for(program, epoch, selector, action))
    for action in actions:
        base.require(0 <= action.payout < 2**31 and action.recipient in (0, 1), 'invalid action')
        total = action.payout + (action.successor.amount if action.successor else 0)
        base.require(amount - total == FEE, 'action does not conserve value and fixed fee')
    grant = cpa.tagged_hash('CPA/v0/Grant', program.program_id + struct.pack('<II', epoch, cap) +
                            base.sha(scope))
    state = struct.pack('<QI', amount, epoch) + grant
    body = _body(program, amount, epoch, cap, grant, state, actions)
    descriptor = cpa.Descriptor(NETWORK, cpa.SEMANTICS, program.program_id, PROFILE, SUITE,
                                cpa.body_hash(body), ABI, DELEGATION, RESOURCES)
    leaf = Leaf(cpa.authority_script(descriptor, cpa.state_root(state), body))
    return Stage(descriptor, program, amount, epoch, cap, grant, state, body, leaf, actions)


def compile_machine(nodes=None, outputs=OUTPUTS, n_inputs: int = 3,
                    cap: int = ROOT_CAP, epoch: int = 0) -> Stage:
    base.require(type(n_inputs) is int and 0 < n_inputs <= MAX_INPUTS, 'input limit')
    selected = NODES if nodes is None else nodes
    base.require(len(selected) <= MAX_NODES, 'gate declaration limit')
    program = cpa.canonical_program(n_inputs, selected, outputs)
    base.require(program.node_count <= MAX_NODES and len(program.output_hashes) == 2,
                 'profile requires at most 32 nodes and exactly two outputs')
    actions = []
    for selector, payout in enumerate((7_000, 9_000)):
        amount = ROOT_AMOUNT - payout - FEE
        terminal_actions = tuple(Action(amount - FEE, recipient, None) for recipient in (0, 1))
        child = _stage(program, amount, epoch + 1, ROOT_AMOUNT, terminal_actions)
        actions.append(Action(payout, selector, child))
    return _stage(program, ROOT_AMOUNT, epoch, cap, tuple(actions))


def witness(stage: Stage, tx: base.Tx, inputs=(1, 1, 0)) -> list[bytes]:
    base.require(len(tx.inputs) >= 1, 'missing input')
    digest = base.sighash(tx, 0, leaf=base.tapleaf(stage.leaf.script))
    item = tx.inputs[0]
    base.require(len(item.script) == 34 and item.script[:2] == b'\x51\x20', 'expected P2TR input')
    _, control = stage.leaf.output()
    proof = [stage.state, stage.authority, stage.state_root, stage.grant, digest,
             statement(stage.authority, stage.state_root, stage.grant, digest),
             item.outpoint(), item.script[2:], base.tapleaf(stage.leaf.script)]
    proof.extend(base.script_number(bit) for bit in trace(stage.program, tuple(inputs)))
    return proof + [stage.leaf.script, control]


def spend(stage: Stage, txid: str, vout: int, inputs=(1, 1, 0)):
    values = dict(zip((key for key, _ in stage.program.records), trace(stage.program, tuple(inputs))))
    selector = values[stage.program.output_hashes[1]]
    tx = base.Tx((base.Input(bytes.fromhex(txid)[::-1], vout, stage.amount,
                             stage.leaf.output()[0]),),
                 outputs_for(stage.program, stage.epoch, selector, stage.actions[selector]))
    return tx, witness(stage, tx, inputs)


def main():
    import json
    stage = compile_machine()
    script, control = stage.leaf.output()
    print(json.dumps({'warning': 'Isolated patched regtest only. Public-network funding is unsafe.',
        'profile': 'disclosed-trace; no zero knowledge', 'program_id': stage.program.program_id.hex(),
        'authority_id': stage.authority.hex(), 'state_root': stage.state_root.hex(),
        'descriptor': stage.descriptor.encode().hex(), 'script_pubkey': script.hex(),
        'address': base.address(script[2:]), 'control_block': control.hex(),
        'script_bytes': len(stage.leaf.script)}, indent=2))


if __name__ == '__main__':
    main()
