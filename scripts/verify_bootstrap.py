"""Independent 140-digit plaintext oracle for every full canonical output slot.

No OpenFHE or C++ reference outputs are imported. Checks the complete multiplication
chain against the input/factor, refresh restoration, shape, totals and acceptance.
"""
import argparse
from decimal import Decimal, localcontext
import json
from pathlib import Path


def verify(path):
    with localcontext() as ctx:
        ctx.prec = 140
        r = json.loads(Path(path).read_text(), parse_float=Decimal)
        D = Decimal
        p = r['profile']
        n, slots = p['N'], p['slots']
        assert p['security_bits'] in (128, 192, 256)
        assert p['required_N'] <= n
        def product(name):
            value = 1
            primes = []
            for item in p[name]:
                q, root = int(item['prime']), int(item['root'])
                assert q not in primes and (q - 1) % (2*n) == 0
                assert pow(root, n, q) == q - 1
                primes.append(q); value *= q
            assert primes
            return value
        q = product('Q_primes')
        module_p, native_p, t = [product(x) for x in
                               ('module_P_primes', 'native_P_primes', 'public_T_primes')]
        assert max(q*module_p, q*native_p, t).bit_length() == p['checked_public_bits']
        assert len(r['input']) == slots and r['decoded_layout'] == 'all_N_over_2_slots_repeating_input'
        expected = [(D(x), D(y)) for x, y in r['input']]
        factor = tuple(map(D, r['factor']))
        target = D(2) ** -r['precision_bits']
        assert abs(D(r['target_error'])-target) < D('1e-30')
        worst = D(0)
        count = 0
        def check(decoded, reference, reported):
            nonlocal worst, count
            assert len(decoded) == n//2
            error = D(0)
            for i, (a,b) in enumerate(decoded):
                x,y = reference[i % slots]
                actual = ((D(a)-x)**2+(D(b)-y)**2).sqrt()
                assert actual.is_finite()
                error = max(error,actual);count+=1
            assert abs(error-D(reported)) < D('1e-12'), (error, reported)
            worst = max(worst,error)
        check(r['fresh_decoded'], expected, r['fresh_error'])
        check(r['fold_decoded'], expected, r['fold_error'])
        depth, refreshes, last_level = 0, 0, p['total_depth']-1
        total = D(r['timings_ms']['factor_fold_ms'])
        for record in r['records']:
            assert record['level_before'] == last_level
            assert D(record['scale']).is_finite() and D(record['scale']) > 0
            assert D(record['ms']) > 0
            total += D(record['ms'])
            if record['operation'] == 'bootstrap':
                assert record['depth'] == depth
                assert record['level_after'] < record['level_before']
                refreshes += 1
            else:
                assert record['operation'] == 'multiply_rescale'
                assert record['level_after'] > record['level_before']
                depth += 1
                assert record['depth'] == depth
                a,b = factor
                expected = [(x*a-y*b,x*b+y*a) for x,y in expected]
            last_level = record['level_after']
            assert 0 <= last_level <= p['total_depth']
            for ms in record['phases_ms'].values():
                assert D(ms).is_finite() and D(ms) >= 0
            assert sum(map(D,record['phases_ms'].values())) <= D(record['ms'])+D('0.1')
            check(record['decoded'],expected,record['max_error'])
        assert refreshes == r['refresh_count']
        assert abs(total-D(r['timings_ms']['evaluator_total_ms'])) < D('1e-6')
        assert abs(worst-D(r['max_error'])) < D('1e-12')
        needed = 1 if r['validation_scope'] == 'refresh_only' else 2
        passed = depth == r['circuit_depth'] and refreshes >= needed and worst <= target
        assert r['all_checks_passed'] == passed
        return {'independent_oracle_passed':True,'accepted':passed,'checked_slots':count,
                'max_error':str(worst),'depth':depth,'refreshes':refreshes}


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('report',type=Path)
    args=parser.parse_args()
    result=verify(args.report);print(json.dumps(result,indent=2))
    raise SystemExit(0 if result['accepted'] else 2)
