"""Independent Python integer oracle; matches Spiral v0.2's 12,037 + 293 cases.

Source: patrickdugan/Spiral@7f5ad9f95fce8c40919e360000ca86c7119ceb5c,
BIPSpace/Bounded-Modular-Arithmetic/test_native.py.
Print four LE byte strings and the expected residue (ERR for malformed values).
"""
import itertools
import random


def args(a, b, c, m):
    width = (m.bit_length() + 7) // 8
    return tuple(x.to_bytes(width, "little") for x in (a, b, c, m))


def valid():
    for m in range(2, 14):
        for a, b, c in itertools.product(range(m), repeat=3):
            yield args(a, b, c, m)
    rng = random.Random(20261112)
    for width in range(1, 33):
        for _ in range(64):
            m = rng.randrange(max(2, 1 << (8 * (width - 1))), 1 << (8 * width))
            yield args(*(rng.randrange(m) for _ in range(3)), m)
    for width in range(1, 33):
        for m in sorted({max(2, 1 << (8 * (width - 1))), (1 << (8 * width)) - 1}):
            for a, b, c in itertools.product(sorted({0, 1, m - 1}), repeat=3):
                yield args(a, b, c, m)


def invalid():
    yield (b"",) * 4
    for m in (b"\x00", b"\x01", b"\x11\x00", bytes([1]) * 33):
        yield (bytes(len(m)),) * 3 + (m,)
    for width in range(1, 33):
        m = (1 << (8 * width)) - 1
        good = list(args(1, 1, 1, m))
        for position in range(3):
            for bad in (bytes(width - 1), bytes(width + 1), m.to_bytes(width, "little")):
                changed = good.copy()
                changed[position] = bad
                yield tuple(changed)


def main():
    good = bad = 0
    for case in valid():
        a, b, c, m = (int.from_bytes(x, "little") for x in case)
        residue = ((a * b + c) % m).to_bytes(len(case[-1]), "little")
        print(*(x.hex() or "-" for x in case), residue.hex())
        good += 1
    for case in invalid():
        print(*(x.hex() or "-" for x in case), "ERR")
        bad += 1
    assert (good, bad) == (12037, 293)


if __name__ == "__main__":
    main()
