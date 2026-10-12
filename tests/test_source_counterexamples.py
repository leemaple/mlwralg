"""Independent small-ring counterexamples to the unmodified disclosure.

No OpenFHE calls, approximate arithmetic, or private key is used by recover().
Small parameters demonstrate algebraic failures, not estimates of attack cost.
"""
import json
import math
import random

N = 4
P_PRIMES = [97, 113]
T_PRIMES = [17, 41]
P = math.prod(P_PRIMES)
T = math.prod(T_PRIMES)
H = 193 * 241


def add(a, b, modulus):
    return [(x + y) % modulus for x, y in zip(a, b)]


def sub(a, b, modulus):
    return [(x - y) % modulus for x, y in zip(a, b)]


def mul(a, b, modulus):
    out = [0] * N
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[(i + j) % N] += x * y * (1 if i + j < N else -1)
    return [x % modulus for x in out]


def dot(a, b, modulus):
    out = [0] * N
    for x, y in zip(a, b):
        out = add(out, mul(x, y, modulus), modulus)
    return out


def sr(a, source, target):
    return [((x % source * target + source // 2) // source) % target for x in a]


def solve(matrix, rhs, primes):
    """Invert the 2x2 polynomial map via 8x8 coefficient systems per prime."""
    columns = []
    for j in range(2 * N):
        basis = [[0] * N for _ in range(2)]
        basis[j // N][j % N] = 1
        columns.append(sum([dot(row, basis, math.prod(primes)) for row in matrix], []))
    per_prime = []
    for prime in primes:
        aug = [[columns[j][i] % prime for j in range(2 * N)] + [sum(rhs, [])[i] % prime]
               for i in range(2 * N)]
        for j in range(2 * N):
            pivot = next((i for i in range(j, 2 * N) if aug[i][j]), None)
            if pivot is None:
                return None
            aug[j], aug[pivot] = aug[pivot], aug[j]
            inverse = pow(aug[j][j], -1, prime)
            aug[j] = [v * inverse % prime for v in aug[j]]
            for i in range(2 * N):
                if i != j:
                    factor = aug[i][j]
                    aug[i] = [(a - factor * b) % prime for a, b in zip(aug[i], aug[j])]
        per_prime.append([row[-1] for row in aug])
    modulus = math.prod(primes)
    result = [sum(values[i] * (modulus // p) * pow(modulus // p, -1, p)
                  for values, p in zip(per_prime, primes)) % modulus for i in range(2 * N)]
    return [result[:N], result[N:]]


def original_keygen(secret, target, rng):
    initial = [[[rng.randrange(P) for _ in range(N)] for _ in range(2)] for _ in range(2)]
    matrix = [[sr(poly, P, target) for poly in row] for row in initial]
    b = [sr(dot(row, secret, P), P, target) for row in initial]
    return initial, matrix, b


def encrypt(matrix, b, randomizer, embedded_message):
    transpose = list(zip(*matrix))
    c0 = add(sr(dot(b, randomizer, T), T, P), embedded_message, P)
    tail = [sr(dot(row, randomizer, T), T, P) for row in transpose]
    return [c0, *tail]


def recover(matrix, b, ciphertext):
    randomizer = solve(list(zip(*matrix)), [sr(c, P, T) for c in ciphertext[1:]], T_PRIMES)
    if randomizer is None:
        return None
    return sub(ciphertext[0], sr(dot(b, randomizer, T), T, P), P)


def main():
    rng = random.Random(20261012)  # Reproducible public counterexamples only.
    small = lambda: [rng.choice([-1, 0, 1]) for _ in range(N)]
    recovered = 0
    attempts = 0
    while recovered < 32 and attempts < 1000:
        attempts += 1
        secret = [small(), small()]
        _, matrix, b = original_keygen(secret, T, rng)
        message = [rng.randrange(-20, 21) for _ in range(N)]
        embedded = [97 * x % P for x in message]  # Literal P/t with t=113.
        ciphertext = encrypt(matrix, b, [small(), small()], embedded)
        actual = recover(matrix, b, ciphertext)
        if actual is not None:
            if actual != embedded:
                raise AssertionError("Plaintext recovery counterexample failed")
            recovered += 1
    if recovered != 32:
        raise AssertionError("Insufficient invertible examples")

    larger_primes = [257, 337]
    larger = math.prod(larger_primes)
    secret_recoveries = 0
    for _ in range(100):
        secret = [small(), small()]
        initial, matrix, b = original_keygen(secret, larger, rng)
        inverted = [[sr(a, larger, P) for a in row] for row in matrix]
        if inverted != initial:
            raise AssertionError("Injective expansion inversion failed")
        actual = solve(inverted, [sr(x, larger, P) for x in b], P_PRIMES)
        if actual is not None:
            if actual != [[x % P for x in poly] for poly in secret]:
                raise AssertionError("Secret recovery counterexample failed")
            secret_recoveries += 1
    if secret_recoveries < 32:
        raise AssertionError("Insufficient secret recovery examples")

    equal_recoveries = 0
    for _ in range(40):
        secret = [small(), small()]
        initial, matrix, b = original_keygen(secret, P, rng)
        if matrix != initial:
            raise AssertionError("Equal moduli must eliminate rounding")
        actual = solve(matrix, b, P_PRIMES)
        if actual is not None:
            if actual != [[x % P for x in poly] for poly in secret]:
                raise AssertionError("Equal-modulus secret recovery failed")
            equal_recoveries += 1
    if equal_recoveries < 20:
        raise AssertionError("Insufficient equal-modulus recovery examples")

    for _ in range(100):
        secret = [small(), small()]
        matrix = [[[rng.randrange(T) for _ in range(N)] for _ in range(2)] for _ in range(2)]
        for row, source_secret in zip(matrix, secret):
            unrounded = dot(row, secret, T)
            evk_b = add(sr(unrounded, T, P * H), [H * x for x in source_secret], P * H)
            if sr(evk_b, P * H, T) != unrounded:
                raise AssertionError("Switch-key noiseless projection failed")

    # Secret (1, 0); c = (0, 1, 0) decrypts to -1, so c*c must decrypt to +1.
    # Exact relin row (H, 0, 0) contributes +1; the original minus gives -1.
    plus = sr([H, 0, 0, 0], P * H, P)[0]
    minus = (-plus) % P
    if plus != 1 or minus != P - 1:
        raise AssertionError("Relinearization sign counterexample failed")

    # A constant 0.125 slot vector encodes only constant coefficient 0.125.
    if round(0.125) != 0:
        raise AssertionError("Unscaled encoding counterexample failed")
    print(json.dumps({"original_formula_counterexamples": {
        "message_recovery_without_secret_key": recovered,
        "secret_recovery_when_qprime_exceeds_P": secret_recoveries,
        "secret_recovery_when_qprime_equals_P": equal_recoveries,
        "switch_key_noiseless_projection_rows": 200,
        "literal_minus_product": -1, "correct_product": plus,
        "unscaled_0_125_encodes_as": 0}}, indent=2))


if __name__ == "__main__":
    main()
