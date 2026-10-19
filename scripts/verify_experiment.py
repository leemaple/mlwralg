"""Independently recompute reported errors and timing aggregates from observations."""
import json
import math
from pathlib import Path
import statistics
import sys


def close(a, b):
    return math.isclose(a, b, rel_tol=2e-12, abs_tol=1e-25)


def verify_metric(metric, slots, tolerance):
    assert len(metric['expected']) == len(metric['actual']) == len(metric['slot_absolute_errors']) == slots
    errors = [abs(complex(*a) - complex(*b)) for a, b in zip(metric['expected'], metric['actual'])]
    error = max(errors)
    assert all(close(a, b) for a, b in zip(errors, metric['slot_absolute_errors']))
    assert close(metric['max_absolute_error'], error)
    assert error <= tolerance and metric['passes_precision_target'] is True
    assert math.isfinite(metric['scale']) and metric['scale'] > 0
    assert close(metric['log2_scale'], math.log2(metric['scale']))
    assert close(metric['inverse_scale'], 1 / metric['scale'])
    assert close(metric['error_times_scale'], error * metric['scale'])
    assert metric['passes_inverse_scale'] == (error <= 1 / metric['scale'])
    if error == 0:
        assert metric['precision_bits'] is None
    else:
        assert close(metric['precision_bits'], -math.log2(error))


def verify(path):
    report = json.loads(Path(path).read_text())
    protocol = report["protocol"]
    assert report["all_correctness_checks_passed"] is True
    profile = report["profile"]
    n, slots = profile["ring_dimension"], profile["slots"]
    assert n >= 1024 and n <= 131072 and n & (n - 1) == 0
    assert 1 <= slots <= n // 2 and slots & (slots - 1) == 0
    assert 1 <= report["l"] <= 8 and 1 <= report["k"] <= 8
    if report.get('schema_version',1) >= 4:
        assert profile['construction_mode'] == 'compact_pair_bv'
        assert profile['key_switch_technique'] == 'gadget_small_P' and profile['large_digits'] == 0
        assert report['requested_parameters']['compact'] == 1
        # This batch uses 128 classic/ternary limits, including the actual
        # public-key modulus T rather than the smaller post-DCP modulus.
        if report['requested_parameters']['security_bits'] == 128:
            limits={1024:27,2048:54,4096:109,8192:218,16384:438,32768:881,65536:1747,131072:3523}
            assert profile['checked_public_modulus_bits'] <= limits[n]
        public_q=int(report['moduli']['T_public']['modulus'])
        qp=int(report['moduli']['P_main']['modulus'])*int(report['moduli']['Q_auxiliary']['modulus'])
        assert max(public_q.bit_length(),qp.bit_length()) == profile['checked_public_modulus_bits']
        assert public_q > int(report['moduli']['P_main']['modulus'])
        divisor=int(report['moduli']['DCP_divisor'])
        assert int(profile['ciphertext_basis'][-1]['prime']) == divisor
    if "requested_parameters" in report:
        requested = report["requested_parameters"]
        assert requested["l"] == report["l"] and requested["k"] == report["k"]
        assert requested["N"] == 0 or requested["N"] == n
        assert requested["slots"] == slots and requested["depth"] == profile["depth"]
        assert requested["samples"] == protocol["samples_per_operation"]
        assert requested["warmups"] == protocol["warmups_per_operation"]
        assert requested["precision_bits"] == protocol["precision_target_bits"]
        assert requested["key_trials"] == protocol["fresh_key_trials"]
        assert requested["smudge_bound"] == protocol["smudge_bound"]
        assert requested["rotation_steps"] == protocol["rotation_steps"]
        assert profile["rlwe_security_table"] == f'HEStd_{requested["security_bits"]}_classic'
    assert protocol["absolute_tolerance"] == 2 ** (-protocol["precision_target_bits"])
    assert len(report["correctness"]) == protocol["fresh_key_trials"] * protocol["cases_per_key"]
    for case in report["correctness"]:
        bounds = case["coefficient_checks"]
        assert bounds["tensor_identity"] and bounds["all_passed"]
        if report.get('schema_version',1) >= 4:
            assert bounds['dcp_rcb_identity'] and bounds['rs2_rcb_identity']
            assert bounds['high_switch_noise'] <= bounds['single_switch_bound']
            assert bounds['low_switch_noise'] <= bounds['single_switch_bound']
            checks=[case['headroom_check']]+case['depth_circuit']['headroom_checks']
            assert len(checks) == profile['depth']+1
            for check in checks:
                assert check['passed'] is True
                assert check['integer_pair_consistent'] is True
                assert math.isfinite(check['omitted_low_product_slot_max']) and check['omitted_low_product_slot_max']>=0
                assert check['coefficient_bound'] < check['wide_half_modulus']
                assert check['observed_or_bounded_norm'] < check['active_half_modulus']
                if not check['exact_wide_replay']:
                    assert check['observed_or_bounded_norm'] == check['coefficient_bound']
        assert max(bounds["fresh_a"], bounds["fresh_b"]) <= bounds["fresh_bound"]
        assert bounds["relinearize"] <= bounds["relinearize_bound"]
        assert bounds["rescale"] <= bounds["rescale_bound"]
        assert len(case["metrics"]) == 7
        for metric in case["metrics"]:
            verify_metric(metric, slots, protocol['absolute_tolerance'])
        if report.get('schema_version', 1) >= 3:
            circuit = case['depth_circuit']
            assert circuit['circuit'] == 'repeated_square'
            assert len(circuit['input']) == slots
            expected = [complex(*x) for x in circuit['input']]
            assert all(abs(x) <= min(1., requested['message_bound']) + 1e-15 for x in expected)
            assert len(circuit['metrics']) == profile['depth']
            for layer, metric in enumerate(circuit['metrics'], 1):
                expected = [x * x for x in expected]
                assert metric['operation'] == 'depth_square' and metric['level'] == layer + 1
                # Reconstruct the plaintext circuit independently, including
                # the expectation rather than trusting its reported value.
                assert all(abs(a - complex(*b)) <= 1e-13 for a, b in zip(expected, metric['expected']))
                verify_metric(metric, slots, protocol['absolute_tolerance'])
            if report.get('schema_version',1)>=4:
                rotation=circuit['lowest_rotation_metric']
                verify_metric(rotation,slots,protocol['absolute_tolerance'])
                assert rotation['level']==profile['depth']+1
                shifted=expected[protocol['rotation_steps']%slots:]+expected[:protocol['rotation_steps']%slots]
                assert all(abs(a-complex(*b))<=1e-13 for a,b in zip(shifted,rotation['expected']))
    expected_operations = {"keygen", "relin_keygen", "rotation_keygen", "encode", "encrypt_preencoded",
        "decrypt_decode_fresh", "prepare_one_ciphertext", "add", "rotate" if report.get("schema_version", 1) >= 2 else "rotate_left_one", "decrypt_decode_product",
        "multiply_tensor", "multiply_relinearize", "multiply_rescale", "multiply_total"}
    if report.get('schema_version', 1) >= 3:
        expected_operations.add('depth_square_circuit')
    assert set(report["timings"]) == expected_operations
    for item in report["timings"].values():
        samples = item["samples_ms"]
        assert len(samples) == protocol["samples_per_operation"]
        assert all(math.isfinite(x) and x > 0 for x in samples)
        assert close(item["mean_ms"], statistics.mean(samples))
        assert close(item["median_ms"], statistics.median(samples))
        assert close(item["stddev_sample_ms"], statistics.stdev(samples))
        assert item["min_ms"] == min(samples) and item["max_ms"] == max(samples)
        assert item["p95_nearest_rank_ms"] == sorted(samples)[math.ceil(.95 * len(samples)) - 1]
    stages = [report["timings"]["multiply_" + key]["samples_ms"] for key in ("tensor", "relinearize", "rescale", "total")]
    assert all(close(a + b + c, total) for a, b, c, total in zip(*stages))
    print(f"Verified errors, scale comparisons and timing statistics: {path}")
    return report


if __name__ == "__main__":
    reports = [verify(path) for path in sys.argv[1:]]
    assert reports, "Supply at least one experiment.json"
    if len(reports) > 1:
        assert all(r["source_identity"] == reports[0]["source_identity"] for r in reports[1:])
        assert all(r["profile"] == reports[0]["profile"] and r["moduli"] == reports[0]["moduli"] for r in reports[1:])
        assert all((r["l"], r["k"]) == (reports[0]["l"], reports[0]["k"]) for r in reports[1:])
        print("Implementation identity and all reported parameters match across environments")
