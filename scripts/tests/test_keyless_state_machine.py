"""Check the finite transition relation and compiled Script against independent oracles."""
from dataclasses import replace
import hashlib
from pathlib import Path
import struct
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/research'))
import keyless_checksig_rpc as base
import keyless_state_machine as machine


class ScriptFailure(ValueError):
    pass


def number(raw):
    if len(raw) > 4:
        raise ScriptFailure('numeric width')
    if not raw:
        return 0
    value = int.from_bytes(raw, 'little')
    return -(value & ~(0x80 << (8 * (len(raw)-1)))) if raw[-1] & 0x80 else value


def encode_number(value):
    if value == 0:
        return b''
    raw = bytearray(abs(value).to_bytes((abs(value).bit_length()+7)//8, 'little'))
    if raw[-1] & 0x80:
        raw.append(0x80 if value < 0 else 0)
    elif value < 0:
        raw[-1] |= 0x80
    return bytes(raw)


def execute(script, items, actual_digest):
    stack, alt, conditions = list(items), [], []

    def bounds():
        if len(stack) + len(alt) > 1000 or any(len(item) > 520 for item in stack + alt):
            raise ScriptFailure('stack bound')

    def pop():
        if not stack:
            raise ScriptFailure('stack underflow')
        return stack.pop()

    def true(raw):
        return any(byte != 0 for byte in raw[:-1]) or bool(raw and raw[-1] not in (0, 128))

    bounds()
    position = 0
    while position < len(script):
        opcode = script[position]
        position += 1
        literal = None
        if 1 <= opcode <= 75:
            literal = script[position:position+opcode]
            if len(literal) != opcode:
                raise ScriptFailure('truncated push')
            position += opcode
        enabled = all(conditions)
        if opcode == 0x63:
            condition = pop() if enabled else b''
            if condition not in (b'', b'\x01'):
                raise ScriptFailure('MINIMALIF')
            conditions.append(enabled and condition == b'\x01')
            continue
        if opcode == 0x67:
            if not conditions:
                raise ScriptFailure('unbalanced ELSE')
            conditions[-1] = not conditions[-1]
            continue
        if opcode == 0x68:
            if not conditions:
                raise ScriptFailure('unbalanced ENDIF')
            conditions.pop()
            continue
        if not enabled:
            continue
        if literal is not None:
            stack.append(literal)
        elif opcode == 0:
            stack.append(b'')
        elif 0x51 <= opcode <= 0x60:
            stack.append(encode_number(opcode - 0x50))
        elif opcode == 0x69:
            if not true(pop()):
                raise ScriptFailure('VERIFY')
        elif opcode == 0x6b:
            alt.append(pop())
        elif opcode == 0x6c:
            if not alt:
                raise ScriptFailure('altstack underflow')
            stack.append(alt.pop())
        elif opcode == 0x75:
            pop()
        elif opcode == 0x79:
            index = number(pop())
            if index < 0 or index >= len(stack):
                raise ScriptFailure('PICK index')
            stack.append(stack[-index-1])
        elif opcode == 0x7c:
            right, left = pop(), pop()
            stack.extend((right, left))
        elif opcode == 0x7e:
            right, left = pop(), pop()
            stack.append(left + right)
        elif opcode == 0x82:
            if not stack:
                raise ScriptFailure('SIZE underflow')
            stack.append(encode_number(len(stack[-1])))
        elif opcode == 0x88:
            if pop() != pop():
                raise ScriptFailure('EQUALVERIFY')
        elif opcode == 0x9d:
            if number(pop()) != number(pop()):
                raise ScriptFailure('NUMEQUALVERIFY')
        elif opcode in (0x93, 0x94, 0x9b, 0x9c, 0xa1, 0xa2):
            right, left = number(pop()), number(pop())
            operations = {0x93: lambda: left + right, 0x94: lambda: left - right,
                          0x9b: lambda: bool(left or right), 0x9c: lambda: left == right,
                          0xa1: lambda: left <= right, 0xa2: lambda: left >= right}
            stack.append(encode_number(int(operations[opcode]())))
        elif opcode == 0xa5:
            maximum, minimum, value = number(pop()), number(pop()), number(pop())
            stack.append(encode_number(int(minimum <= value < maximum)))
        elif opcode == 0xa8:
            stack.append(hashlib.sha256(pop()).digest())
        elif opcode == 0xad:
            key, candidate = pop(), pop()
            selected = b'\x02' + hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/TXCOMMIT-draft').digest()
            if key != selected or len(candidate) != 32 or candidate != actual_digest:
                raise ScriptFailure('TXCOMMIT')
        else:
            raise ScriptFailure(f'unsupported opcode {opcode:02x}')
        bounds()
    if conditions or alt:
        raise ScriptFailure('unbalanced execution')
    return stack


def compact(value):
    if value < 253:
        return bytes([value])
    if value <= 65535:
        return b'\xfd' + value.to_bytes(2, 'little')
    return b'\xfe' + value.to_bytes(4, 'little')


def tagged(tag, message):
    prefix = hashlib.sha256(tag.encode('ascii')).digest()
    return hashlib.sha256(prefix + prefix + message).digest()


def output_bytes(output):
    return output.amount.to_bytes(8, 'little') + compact(len(output.script)) + output.script


def transaction_digest(tx, script, *, annex=None):
    digest = lambda value: hashlib.sha256(value).digest()
    prevouts = b''.join(item.txid + item.index.to_bytes(4, 'little') for item in tx.inputs)
    amounts = b''.join(item.amount.to_bytes(8, 'little') for item in tx.inputs)
    scripts = b''.join(compact(len(item.script)) + item.script for item in tx.inputs)
    sequences = b''.join(item.sequence.to_bytes(4, 'little') for item in tx.inputs)
    outputs = b''.join(output_bytes(output) for output in tx.outputs)
    message = (b'\x00\x00' + struct.pack('<iI', tx.version, tx.locktime)
               + digest(prevouts) + digest(amounts) + digest(scripts) + digest(sequences)
               + digest(outputs) + bytes([2 + (annex is not None)]) + bytes(4))
    if annex is not None:
        message += digest(compact(len(annex)) + annex)
    message += tagged('TapLeaf', b'\xc0' + compact(len(script)) + script)
    message += b'\x02\xff\xff\xff\xff'
    return tagged('TapSighash', message)


def final_commitment(program_id, state):
    return tagged('BIPSpace/Keyless-CHECKSIG/F17/state/v1', program_id + bytes(4) + bytes([state]))


class StateMachineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = machine.compile_machine()

    def check(self, stage, tx, witness, *, annex=None):
        self.assertEqual(execute(stage.leaf.script, witness[:-2],
                                 transaction_digest(tx, stage.leaf.script, annex=annex)), [b'\x01'])

    def test_all_four_funded_path_templates_verify_their_entire_trace(self):
        expected = {(2, 2): (9, 15, 0), (2, 3): (9, 1, 1),
                    (3, 2): (12, 1, 1), (3, 3): (12, 4, 0)}
        for path, (middle, final, recipient) in expected.items():
            with self.subTest(path=path):
                first, witness = machine.build_spend(self.root, '42' * 32, 0, path[0])
                self.check(self.root, first, witness)
                self.assertLessEqual(max(map(len, witness[:-2])), 80)
                self.assertEqual(tuple(first.outputs[i].amount for i in range(2)),
                                 (9000, 89000) if middle == 9 else (12000, 86000))
                self.assertEqual(first.outputs[0].script,
                                 b'\x51\x20' + base.RECIPIENTS[0 if middle == 9 else 1])
                child = self.root.branch(middle).successor
                self.assertIsNotNone(child)
                self.assertEqual(child.old_state, middle)
                self.assertEqual(child.depth, 0)
                self.assertEqual(first.outputs[1].script, child.leaf.output()[0])
                _, txid = first.serialize([witness])
                terminal, items = machine.build_spend(child, txid, 1, path[1])
                self.check(child, terminal, items)
                self.assertEqual(terminal.inputs[0].txid, bytes.fromhex(txid)[::-1])
                self.assertEqual(terminal.inputs[0].index, 1)
                self.assertEqual(terminal.inputs[0].script, first.outputs[1].script)
                self.assertEqual(terminal.inputs[0].amount, first.outputs[1].amount)
                self.assertEqual(terminal.outputs[0].amount, 87000 if middle == 9 else 84000)
                self.assertEqual(terminal.outputs[0].script, b'\x51\x20' + base.RECIPIENTS[recipient])
                self.assertEqual(output_bytes(terminal.outputs[1]),
                                 bytes(8) + b'\x22\x6a\x20' + final_commitment(machine.PROGRAM_ID, final))
                self.assertEqual(sum(output.amount for output in first.outputs), 98000)
                self.assertEqual(sum(output.amount for output in terminal.outputs), child.amount-2000)

    def test_alternate_computations_remain_eligible_for_the_same_reserve(self):
        first, left = machine.build_spend(self.root, '43' * 32, 2, 2)
        other, right = machine.build_spend(self.root, '43' * 32, 2, 3)
        self.assertEqual(first.inputs, other.inputs)
        self.assertNotEqual(first.outputs, other.outputs)
        self.check(self.root, first, left)
        self.check(self.root, other, right)
        with self.assertRaisesRegex(ScriptFailure, 'TXCOMMIT'):
            self.check(self.root, other, left)

    def test_fresh_valid_wrong_old_state_cannot_reach_the_authorized_result(self):
        tx, _ = machine.build_spend(self.root, '44' * 32, 0, 2)
        rows = (0, 3, 6, 9)
        self.assertTrue(all(rows[i+1] == (rows[i]+3) % 17 for i in range(3)))
        self.assertEqual(rows[-1], 9)
        witness = machine.witness(tx, self.root, rows, 3)
        with self.assertRaisesRegex(ScriptFailure, 'NUMEQUALVERIFY'):
            self.check(self.root, tx, witness)

    def test_every_arithmetic_edge_is_checked(self):
        tx, _ = machine.build_spend(self.root, '45' * 32, 0, 3)
        for edge, rows in enumerate(((3, 8, 10, 12), (3, 5, 10, 12), (3, 5, 7, 12))):
            self.assertEqual([index for index in range(3)
                              if (rows[index] + 2) % 17 != rows[index + 1]], [edge])
            items = machine.witness(tx, self.root, rows, 2)
            with self.subTest(edge=edge), self.assertRaisesRegex(ScriptFailure, 'NUMEQUALVERIFY'):
                self.check(self.root, tx, items)

    def test_field_encodings_accept_exactly_canonical_zero_through_sixteen(self):
        builder = machine._Builder(['field'])
        machine._canonical_field(builder, 'field')
        builder.op(0x75, 1)
        builder.op(0x51, 0, 'success')
        for value in range(17):
            with self.subTest(value=value):
                self.assertEqual(execute(bytes(builder.code), [encode_number(value)], bytes(32)), [b'\x01'])
        malformed = [b'\x00', b'\x80', b'\x00\x00', b'\x81', b'\x11', b'\xff', bytes(521)]
        malformed += [bytes([value, 0]) for value in range(1, 17)]
        for raw in malformed:
            with self.subTest(raw=raw.hex()), self.assertRaises(ScriptFailure):
                execute(bytes(builder.code), [raw], bytes(32))

    def test_terminal_state_commitment_uses_a_fixed_unsigned_byte_including_zero(self):
        for state in range(17):
            builder = machine._Builder(['row3'])
            machine._state_digest(builder, machine.PROGRAM_ID, 0)
            actual = execute(bytes(builder.code), [encode_number(state)], bytes(32))
            self.assertEqual(actual, [encode_number(state), final_commitment(machine.PROGRAM_ID, state)])
            self.assertEqual(machine.state_commitment(machine.PROGRAM_ID, 0, state), actual[-1])

    def test_program_and_context_witness_fields_are_bound(self):
        tx, witness = machine.build_spend(self.root, '46' * 32, 0, 2)
        for name in ('program_id', 'outpoint', 'spent_key', 'tapleaf'):
            position = machine.WITNESS_FIELDS[name]
            original = witness[position]
            for changed in (original[1:], original+b'\x00', bytes([original[0]^1])+original[1:]):
                items = witness.copy()
                items[position] = changed
                with self.subTest(field=name, length=len(changed)), self.assertRaises(ScriptFailure):
                    self.check(self.root, tx, items)

    def test_single_input_value_sequence_version_locktime_and_no_annex_are_enforced(self):
        tx, witness = machine.build_spend(self.root, '47' * 32, 0, 2)
        altered = [replace(tx, version=1), replace(tx, locktime=1),
                   replace(tx, inputs=(replace(tx.inputs[0], sequence=0xfffffffe),)),
                   replace(tx, inputs=(replace(tx.inputs[0], amount=100001),)),
                   replace(tx, inputs=tx.inputs+(replace(tx.inputs[0], index=1),))]
        for other in altered:
            fresh = machine.witness(other, self.root, (3, 5, 7, 9), 2)
            with self.subTest(tx=other), self.assertRaisesRegex(ScriptFailure, 'TXCOMMIT'):
                self.check(self.root, other, fresh)
        with self.assertRaisesRegex(ScriptFailure, 'TXCOMMIT'):
            self.check(self.root, tx, witness, annex=b'\x50fresh-annex')

    def test_outpoint_changes_require_a_fresh_witness_and_allow_another_funded_reserve(self):
        tx, witness = machine.build_spend(self.root, '48' * 32, 0, 2)
        other = replace(tx, inputs=(replace(tx.inputs[0], txid=bytes.fromhex('49'*32), index=2),))
        with self.assertRaisesRegex(ScriptFailure, 'TXCOMMIT'):
            self.check(self.root, other, witness)
        self.check(self.root, other, machine.witness(other, self.root, (3, 5, 7, 9), 2))

    def test_checked_result_constrains_recipient_amount_and_complete_successor(self):
        tx, _ = machine.build_spend(self.root, '50' * 32, 0, 2)
        alternate_program = machine.compile_machine(hashlib.sha256(b'other-program').digest())
        false_program = alternate_program.branch(9).successor.leaf.output()[0]
        false_state = self.root.branch(12).successor.leaf.output()[0]
        altered_outputs = [
            (replace(tx.outputs[0], script=b'\x51\x20'+base.RECIPIENTS[1]), tx.outputs[1]),
            (replace(tx.outputs[0], amount=8999), tx.outputs[1]),
            (replace(tx.outputs[0], amount=9001), replace(tx.outputs[1], amount=88999)),
            (tx.outputs[0], replace(tx.outputs[1], script=false_program)),
            (tx.outputs[0], replace(tx.outputs[1], script=false_state)),
            tx.outputs[::-1], tx.outputs+(base.Output(0, b'\x6a'),), tx.outputs[:1],
        ]
        for outputs in altered_outputs:
            other = replace(tx, outputs=outputs)
            fresh = machine.witness(other, self.root, (3, 5, 7, 9), 2)
            with self.subTest(outputs=outputs), self.assertRaisesRegex(ScriptFailure, 'TXCOMMIT'):
                self.check(self.root, other, fresh)

    def test_terminal_commitment_rejects_state_depth_and_program_substitution(self):
        stage = self.root.branch(9).successor
        tx, _ = machine.build_spend(stage, '51' * 32, 1, 2)
        for data in (final_commitment(machine.PROGRAM_ID, 1),
                     tagged('BIPSpace/Keyless-CHECKSIG/F17/state/v1',
                            machine.PROGRAM_ID + struct.pack('<I', 1) + b'\x0f'),
                     final_commitment(hashlib.sha256(b'other-program').digest(), 15)):
            other = replace(tx, outputs=(tx.outputs[0], base.Output(0, b'\x6a\x20'+data)))
            fresh = machine.witness(other, stage, (9, 11, 13, 15), 2)
            with self.subTest(commitment=data.hex()), self.assertRaisesRegex(ScriptFailure, 'TXCOMMIT'):
                self.check(stage, other, fresh)

    def test_prior_stage_proof_cannot_be_replayed_at_a_successor(self):
        stage = self.root.branch(9).successor
        tx, _ = machine.build_spend(stage, '52' * 32, 1, 2)
        with self.assertRaisesRegex(ScriptFailure, 'NUMEQUALVERIFY'):
            self.check(stage, tx, machine.witness(tx, stage, (3, 5, 7, 9), 2))

    def test_trace_builder_matches_the_bounded_field_relation(self):
        for old in range(17):
            for delta in (2, 3):
                rows = machine.trace(old, delta)
                self.assertEqual(rows[0], old)
                self.assertEqual(len(rows), 4)
                for left, right in zip(rows, rows[1:]):
                    self.assertEqual((right-left) % 17, delta)
        for old, delta in ((-1, 2), (17, 2), (3, 0), (3, 1), (3, 4), (True, 2)):
            with self.subTest(old=old, delta=delta), self.assertRaises(ValueError):
                machine.trace(old, delta)


if __name__ == '__main__':
    unittest.main()
