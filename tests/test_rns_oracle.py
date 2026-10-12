"""Check C++ RNS/NTT results using independent Python integer arithmetic."""
import json
import math
import random
from pathlib import Path
import subprocess
import sys


def convolution(a, b, modulus):
    n = len(a)
    out = [0] * n
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[(i + j) % n] += x * y * (1 if i + j < n else -1)
    return [x % modulus for x in out]


def automorphism(a, exponent, modulus):
    n = len(a)
    out = [0] * n
    for i, x in enumerate(a):
        position = i * exponent % (2 * n)
        out[position % n] += x if position < n else -x
    return [x % modulus for x in out]


def main(executable):
    rng = random.Random(20261012)  # Test vectors only; never used for keys.
    lines, answers = [], []

    def add(operation, primes, target, a, b=(), steps=0, expected=None):
        n, q, p = len(a), math.prod(primes), math.prod(target)
        a = [x % q for x in a]
        b = [x % q for x in b]
        fields = [operation, n, len(primes), len(target), steps, *primes, *target, *a, *b]
        lines.append(" ".join(map(str, fields)))
        if expected is not None:
            answers.append(expected)
        elif operation == "round":
            answers.append([((x * p + q // 2) // q) % p for x in a])
        elif operation == "lift":
            answers.append([(x if x <= q // 2 else x - q) % p for x in a])
        elif operation == "select":
            answers.append([x % p for x in a])
        elif operation == "mul":
            answers.append(convolution(a, b, q))
        elif operation == "rotate":
            answers.append(automorphism(a, pow(5, steps % (n // 2), 2 * n), q))
        else:
            answers.append(a)

    bases = [
        ([17, 97], [113, 193]),
        ([113, 193], [17, 97]),
        ([1152921504606748673, 1125899912052737, 1125899904679937],
         [1125899908022273, 557057]),
    ]
    fixture = json.loads((Path(__file__).parent / "fixtures/parameters.json").read_text())
    main_primes = [int(x["prime"]) for x in fixture["profile"]["ciphertext_basis"]]
    auxiliary = [int(x["prime"]) for x in fixture["profile"]["auxiliary_basis"]]
    public = list(map(int, fixture["public_modulus_primes"]))
    source = list(map(int, fixture["source_modulus_primes"]))
    bases.extend([(source, main_primes + auxiliary), (public, main_primes),
                  (main_primes + auxiliary, main_primes)])
    for primes, target in bases:
        q = math.prod(primes)
        for n in (8, 16):
            if any((p - 1) % (2 * n) for p in [*primes, *target]):
                continue
            boundaries = ([0, 1, q - 1, q // 2, q // 2 + 1, q // 3, -1, -2] * 2)[:n]
            vectors = [boundaries] + [[rng.randrange(q) for _ in range(n)] for _ in range(8)]
            for a in vectors:
                for operation in ("identity", "round", "lift"):
                    add(operation, primes, target, a)
                add("select", primes, primes[:1], a)
                add("mul", primes, target, a, [rng.randrange(q) for _ in range(n)])
                for steps in (-3, -1, 0, 1, 2, n // 2 + 1):
                    add("rotate", primes, target, a, steps=steps)
    for primes in ([17, 17], [19], [49], [17]):
        invalid_target = [193] if primes != [17] else [97]
        operation = "identity" if primes != [17] else "select"
        add(operation, primes, invalid_target, [0] * 8, expected={"error": True})

    proc = subprocess.run([executable], input="\n".join(lines) + "\n", text=True,
                          capture_output=True, check=True, timeout=120)
    actual = [json.loads(line) for line in proc.stdout.splitlines()]
    if len(actual) != len(answers):
        raise AssertionError(f"Expected {len(answers)} outputs; received {len(actual)}: {proc.stderr}")
    for i, (observed, expected) in enumerate(zip(actual, answers)):
        if observed != expected:
            raise AssertionError(f"Oracle mismatch in case {i}: {lines[i]}\n{observed=}\n{expected=}")
    max_bits = max(math.prod(primes).bit_length() for primes, _ in bases)
    print(f"PASS: {len(answers)} independent exact RNS/NTT cases (up to {max_bits}-bit coefficients)")


if __name__ == "__main__":
    main(sys.argv[1])
