"""Audit complete coverage, rejection provenance, and successful observations."""
import csv
import hashlib
import itertools
import json
from pathlib import Path
import re
import sys

from verify_experiment import verify


def check(path):
    folder = Path(path)
    report = json.loads((folder / 'summary.json').read_text())
    expected = set(itertools.product((2,), (2, 3), (4096, 8192, 16384), range(1, 11)))
    rows = report['results']
    assert len(rows) == len(expected) == report['expected_cases'] == 60
    assert {(r['l'], r['k'], r['N'], r['depth']) for r in rows} == expected
    assert report['all_combinations_attempted'] is True
    counts = {status: sum(r['status'] == status for r in rows) for status in {r['status'] for r in rows}}
    assert counts == report['counts']
    assert report['all_combinations_passed'] == (counts.get('passed') == 60)
    for r in rows:
        case = folder / 'cases' / r['case_id']
        assert json.loads((case / 'result.json').read_text()) == r
        assert r['security_bits'] == r['requested_parameters']['security_bits'] == 128
        assert r['requested_parameters'] == dict(report['base_parameters'], l=r['l'], k=r['k'], N=r['N'], depth=r['depth'])
        text = ''.join(f'{key} = {value}\n' for key, value in r['requested_parameters'].items())
        assert (case / 'requested.conf').read_text() == text
        for name, digest in r['evidence_sha256'].items():
            assert hashlib.sha256((case / name).read_bytes()).hexdigest() == digest, (r['case_id'], name)
        if r['status'] == 'security_rejected':
            assert r['preflight_exit_code'] == 1
            error = (case / 'preflight.log').read_text()
            match = re.search(r'The specified ring dimension \((\d+)\) does not comply with HE standards recommendation \((\d+)\)\.', error)
            assert match and int(match[1]) == r['N'] and int(match[2]) == r['minimum_recommended_N'] > r['N']
            assert 'timings' not in r and 'depth_max_error' not in r and 'experiment_exit_code' not in r
            assert not (case / 'experiment.json').exists()
        elif r['status'] == 'passed':
            assert r['preflight_exit_code'] == r['experiment_exit_code'] == 0
            preflight = json.loads((case / 'preflight.json').read_text())
            actual = verify(case / 'experiment.json')
            assert actual['schema_version'] >= 3
            assert actual['source_identity'] == report['source_identity']
            assert actual['source_commit'] == report['source_commit']
            assert actual['environment']['executable_sha256'] == report['environment']['executable_sha256']
            assert actual['requested_parameters'] == preflight['requested_parameters'] == r['requested_parameters']
            assert actual['profile'] == preflight['profile'] and actual['moduli'] == preflight['moduli']
            assert actual['timings'] == r['timings']
            metrics = [m for c in actual['correctness'] for m in c['metrics']]
            deep = [m for c in actual['correctness'] for m in c['depth_circuit']['metrics']]
            assert r['decrypt_max_error'] == max(m['max_absolute_error'] for m in metrics if m['operation'].startswith('decrypt_'))
            assert r['multiply_max_error'] == max(m['max_absolute_error'] for m in metrics if m['operation'] == 'multiply_after_rescale')
            assert r['depth_max_error'] == max(m['max_absolute_error'] for m in deep)
            assert r['strict_inverse_scale_passed'] == sum(m['passes_inverse_scale'] for m in metrics + deep)
            assert r['strict_inverse_scale_total'] == len(metrics) + len(deep)
        else:
            raise AssertionError(f'Unexpected failure in {r["case_id"]}: {r["status"]}: {r["reason"]}')
    with (folder / 'summary.csv').open(encoding='utf-8-sig') as stream:
        csv_rows = list(csv.DictReader(stream))
    assert len(csv_rows) == 60
    for csv_row, row in zip(csv_rows, rows):
        assert csv_row['status'] == row['status']
        assert tuple(int(csv_row[key]) for key in ('l', 'k', 'N', 'depth')) == tuple(row[key] for key in ('l', 'k', 'N', 'depth'))
        if row['status'] == 'security_rejected':
            assert csv_row['depth_max_error'] == '' and all(value == '' for key, value in csv_row.items() if key.endswith('_mean_ms'))
    print(f'Complete grid verified: 60 unique cases, {counts}; {folder}')
    return report


if __name__ == '__main__':
    assert len(sys.argv) >= 2, 'Supply one or more grid directories'
    reports = [check(path) for path in sys.argv[1:]]
    if len(reports) > 1:
        for report_index, other in enumerate(reports[1:], 2):
            assert other['source_identity'] == reports[0]['source_identity']
            assert other['runner_sha256'] == reports[0]['runner_sha256']
            assert other['base_parameters'] == reports[0]['base_parameters']
            assert other['counts'] == reports[0]['counts']
            for a, b in zip(reports[0]['results'], other['results']):
                assert a['case_id'] == b['case_id'] and a['status'] == b['status']
                assert a['requested_parameters'] == b['requested_parameters']
                if a['status'] == 'passed':
                    left = json.loads((Path(sys.argv[1]) / 'cases' / a['case_id'] / 'experiment.json').read_text())
                    right = json.loads((Path(sys.argv[report_index]) / 'cases' / b['case_id'] / 'experiment.json').read_text())
                    assert left['profile'] == right['profile'] and left['moduli'] == right['moduli']
        print('Both environments match in implementation, complete grid, actual profiles and moduli')
