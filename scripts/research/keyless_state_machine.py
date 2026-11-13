"""Compile a finite F17 state machine whose checked result determines its outputs.

Every witness reveals all four arithmetic rows. Each NUMS P2TR leaf commits its
old state and exact successor programs; the terminal commitment includes the
program identity, remaining depth, and computed state.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct

import keyless_checksig_rpc as base


PROGRAM_ID = base.sha(b'BIPSpace/Keyless-CHECKSIG/F17/full-trace/v1')
STATE_TAG = 'BIPSpace/Keyless-CHECKSIG/F17/state/v1'
FEE = 2_000
ROOT_AMOUNT = 100_000
RECIPIENT_INDEX = {9: 0, 12: 1, 15: 0, 1: 1, 4: 0}
WITNESS_FIELDS = {'program_id': 0, 'outpoint': 1, 'spent_key': 2, 'tapleaf': 3,
                  'delta': 4, 'row0': 5, 'row1': 6, 'row2': 7, 'row3': 8}

OP_IF, OP_ELSE, OP_ENDIF, OP_VERIFY = 0x63, 0x67, 0x68, 0x69
OP_TOALTSTACK, OP_FROMALTSTACK, OP_DROP = 0x6b, 0x6c, 0x75
OP_PICK, OP_SWAP, OP_CAT, OP_SIZE = 0x79, 0x7c, 0x7e, 0x82
OP_EQUALVERIFY, OP_ADD, OP_SUB = 0x88, 0x93, 0x94
OP_BOOLOR, OP_NUMEQUAL, OP_NUMEQUALVERIFY = 0x9b, 0x9c, 0x9d
OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_WITHIN = 0xa1, 0xa2, 0xa5
OP_SHA256, OP_CHECKSIGVERIFY, OP_TRUE = 0xa8, 0xad, 0x51


@dataclass(frozen=True)
class Branch:
    result: int
    recipient_index: int
    payout_sats: int
    successor: Stage | None


@dataclass(frozen=True)
class Stage:
    program_id: bytes
    depth: int
    old_state: int
    amount: int
    leaf: base.Leaf
    branches: tuple[Branch, ...]

    def branch(self, result: int) -> Branch:
        for branch in self.branches:
            if branch.result == result:
                return branch
        raise ValueError('result has no authorized successor')


def trace(old_state: int, delta: int) -> tuple[int, int, int, int]:
    base.require(type(old_state) is int and 0 <= old_state < 17, 'invalid old state')
    base.require(type(delta) is int and delta in (2, 3), 'invalid increment')
    return tuple((old_state + step * delta) % 17 for step in range(4))


def state_commitment(program_id: bytes, depth: int, state: int) -> bytes:
    base.require(len(program_id) == 32, 'invalid program identity width')
    base.require(type(depth) is int and 0 <= depth <= 0xffffffff, 'invalid state depth')
    base.require(type(state) is int and 0 <= state < 17, 'invalid state value')
    return base.tagged(STATE_TAG, program_id + struct.pack('<I', depth) + bytes([state]))


def authorized_outputs(stage: Stage, result: int) -> tuple[base.Output, ...]:
    branch = stage.branch(result)
    payout = base.Output(branch.payout_sats, b'\x51\x20' + base.RECIPIENTS[branch.recipient_index])
    if branch.successor is not None:
        script, _ = branch.successor.leaf.output()
        return payout, base.Output(branch.successor.amount, script)
    commitment = state_commitment(stage.program_id, stage.depth, result)
    return payout, base.Output(0, b'\x6a\x20' + commitment)


class _Builder:
    def __init__(self, stack=()):
        self.stack = list(stack)
        self.code = bytearray()

    def op(self, opcode: int, consumed: int = 0, result: str | None = None):
        base.require(consumed <= len(self.stack), 'compiler stack underflow')
        if consumed:
            del self.stack[-consumed:]
        self.code.append(opcode)
        if result is not None:
            self.stack.append(result)

    def const(self, value: bytes, name: str = ''):
        self.code.extend(base.push(value))
        self.stack.append(name)

    def number(self, value: int, name: str = ''):
        self.const(base.script_number(value), name)

    def pick(self, name: str):
        distance = self.stack[::-1].index(name)
        self.number(distance)
        self.op(OP_PICK, 1, name)

    def rename(self, name: str):
        base.require(bool(self.stack), 'compiler cannot rename empty stack')
        self.stack[-1] = name

    def cat(self, name: str = ''):
        self.op(OP_CAT, 2, name)

    def swap(self):
        base.require(len(self.stack) >= 2, 'compiler swap underflow')
        self.code.append(OP_SWAP)
        self.stack[-2:] = self.stack[-2:][::-1]

    def width(self, name: str, size: int):
        self.pick(name)
        self.op(OP_SIZE, 0, '')
        self.number(size)
        self.op(OP_EQUALVERIFY, 2)
        self.op(OP_DROP, 1)

    def tag(self, name: str, result: str):
        self.const(base.sha(name.encode('ascii')) * 2)
        self.swap()
        self.cat()
        self.op(OP_SHA256, 1, result)

    def conditional(self, yes, no):
        base.require(bool(self.stack), 'compiler conditional underflow')
        self.stack.pop()
        left, right = _Builder(self.stack), _Builder(self.stack)
        yes(left)
        no(right)
        base.require(left.stack == right.stack, 'compiler branches leave different stacks')
        self.code.extend(bytes([OP_IF]) + left.code + bytes([OP_ELSE]) + right.code
                         + bytes([OP_ENDIF]))
        self.stack = left.stack


def _canonical_field(builder: _Builder, name: str):
    builder.pick(name)
    builder.op(OP_SIZE, 0, '')
    builder.number(1)
    builder.op(OP_LESSTHANOREQUAL, 2, '')
    builder.op(OP_VERIFY, 1)
    builder.number(0)
    builder.number(17)
    builder.op(OP_WITHIN, 3, '')
    builder.op(OP_VERIFY, 1)
    builder.pick(name)
    builder.number(0)
    builder.op(OP_NUMEQUAL, 2, '')
    builder.conditional(lambda b: b.width(name, 0), lambda b: b.width(name, 1))


def _checked_trace(builder: _Builder, old_state: int):
    for name in ('delta', 'row0', 'row1', 'row2', 'row3'):
        _canonical_field(builder, name)
    builder.pick('delta')
    builder.number(2)
    builder.op(OP_NUMEQUAL, 2, '')
    builder.pick('delta')
    builder.number(3)
    builder.op(OP_NUMEQUAL, 2, '')
    builder.op(OP_BOOLOR, 2, '')
    builder.op(OP_VERIFY, 1)
    builder.pick('row0')
    builder.number(old_state)
    builder.op(OP_NUMEQUALVERIFY, 2)
    for index in range(3):
        builder.pick(f'row{index}')
        builder.pick('delta')
        builder.op(OP_ADD, 2, 'sum')
        builder.pick('sum')
        builder.number(17)
        builder.op(OP_GREATERTHANOREQUAL, 2, '')

        def reduce(b):
            b.number(17)
            b.op(OP_SUB, 2, 'next')

        builder.conditional(reduce, lambda b: b.rename('next'))
        builder.pick(f'row{index+1}')
        builder.op(OP_NUMEQUALVERIFY, 2)


def _state_digest(builder: _Builder, program_id: bytes, depth: int):
    builder.const(program_id + struct.pack('<I', depth))
    builder.pick('row3')
    builder.pick('row3')
    builder.number(0)
    builder.op(OP_NUMEQUAL, 2, '')

    def zero(b):
        b.op(OP_DROP, 1)
        b.const(b'\x00', 'state_byte')

    builder.conditional(zero, lambda b: b.rename('state_byte'))
    builder.cat()
    builder.tag(STATE_TAG, 'state_commitment')


def _branch_outputs(builder: _Builder, program_id: bytes, depth: int, branch: Branch):
    builder.pick('row3')
    builder.number(branch.result)
    builder.op(OP_NUMEQUALVERIFY, 2)
    payout = base.Output(branch.payout_sats,
                         b'\x51\x20' + base.RECIPIENTS[branch.recipient_index])
    builder.const(payout.serialize())
    if branch.successor is not None:
        script, _ = branch.successor.leaf.output()
        builder.const(base.Output(branch.successor.amount, script).serialize())
    else:
        _state_digest(builder, program_id, depth)
        builder.const(bytes(8) + b'\x22\x6a\x20')
        builder.swap()
        builder.cat()
    builder.cat()
    builder.op(OP_SHA256, 1, 'outputs_hash')


def _compile_stage(program_id: bytes, depth: int, old_state: int, amount: int,
                   branches: tuple[Branch, Branch]) -> Stage:
    builder = _Builder(WITNESS_FIELDS)
    builder.pick('program_id')
    builder.const(program_id)
    builder.op(OP_EQUALVERIFY, 2)
    for name, width in (('outpoint', 36), ('spent_key', 32), ('tapleaf', 32)):
        builder.width(name, width)
    _checked_trace(builder, old_state)
    builder.pick('row3')
    builder.number(branches[0].result)
    builder.op(OP_NUMEQUAL, 2, '')
    builder.conditional(
        lambda b: _branch_outputs(b, program_id, depth, branches[0]),
        lambda b: _branch_outputs(b, program_id, depth, branches[1]),
    )
    builder.const(b'\x00\x00' + struct.pack('<iI', 2, 0))
    builder.pick('outpoint')
    builder.op(OP_SHA256, 1, '')
    builder.cat()
    builder.const(base.sha(struct.pack('<Q', amount)))
    builder.cat()
    builder.const(b'\x22\x51\x20')
    builder.pick('spent_key')
    builder.cat()
    builder.op(OP_SHA256, 1, '')
    builder.cat()
    builder.const(base.sha(struct.pack('<I', 0xfffffffd)))
    builder.cat()
    builder.pick('outputs_hash')
    builder.cat()
    builder.const(b'\x02' + bytes(4))
    builder.cat()
    builder.pick('tapleaf')
    builder.cat()
    builder.const(b'\x02' + b'\xff' * 4)
    builder.cat()
    builder.tag('TapSighash', 'digest')
    builder.op(OP_TOALTSTACK, 1)
    while builder.stack:
        builder.op(OP_DROP, 1)
    builder.op(OP_FROMALTSTACK, 0, 'digest')
    builder.const(base.TXCOMMIT_KEY)
    builder.op(OP_CHECKSIGVERIFY, 2)
    builder.op(OP_TRUE, 0, 'success')
    return Stage(program_id, depth, old_state, amount, base.Leaf(bytes(builder.code)), branches)


def compile_machine(program_id: bytes = PROGRAM_ID) -> Stage:
    base.require(isinstance(program_id, bytes) and len(program_id) == 32,
                 'program identity must be 32 bytes')
    initial_branches = []
    for delta in (2, 3):
        old_state = (3 + 3 * delta) % 17
        payout = old_state * 1_000
        amount = ROOT_AMOUNT - payout - FEE
        branches = tuple(Branch((old_state + 3 * next_delta) % 17,
                                RECIPIENT_INDEX[(old_state + 3 * next_delta) % 17],
                                amount - FEE, None) for next_delta in (2, 3))
        successor = _compile_stage(program_id, 0, old_state, amount, branches)
        initial_branches.append(Branch(old_state, RECIPIENT_INDEX[old_state], payout, successor))
    return _compile_stage(program_id, 1, 3, ROOT_AMOUNT, tuple(initial_branches))


def witness(tx: base.Tx, stage: Stage, rows, delta: int, *, program_id: bytes | None = None):
    base.require(len(rows) == 4, 'four rows are required')
    base.require(bool(tx.inputs), 'witness requires an input')
    spent = tx.inputs[0]
    base.require(len(spent.script) == 34 and spent.script[:2] == b'\x51\x20',
                 'witness requires a P2TR spent output')
    _, control = stage.leaf.output()
    return [stage.program_id if program_id is None else program_id, spent.outpoint(),
            spent.script[2:], base.tapleaf(stage.leaf.script), base.script_number(delta),
            *(base.script_number(row) for row in rows), stage.leaf.script, control]


def build_spend(stage: Stage, funding_txid_display: str, vout: int, delta: int):
    rows = trace(stage.old_state, delta)
    script, _ = stage.leaf.output()
    tx = base.Tx((base.Input(bytes.fromhex(funding_txid_display)[::-1], vout,
                            stage.amount, script),), authorized_outputs(stage, rows[-1]))
    return tx, witness(tx, stage, rows, delta)
