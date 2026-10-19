"""Run every requested tuple; preserve rejected configurations as evidence.

No automatic N increase, modulus reduction, or security bypass is performed.
Each accepted configuration must pass correctness before any timing is emitted.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import html
import itertools
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from run_experiment import command, digest, environment, source_identity, write_csv
from verify_experiment import verify

SECURITY_ERROR = re.compile(r'The specified ring dimension \((\d+)\) does not comply with HE standards recommendation \((\d+)\)\.')
GRID = list(itertools.product((2,), (2, 3), (4096, 8192, 16384), range(1, 11)))


def case_id(l, k, n, depth):
    return f'l{l}-k{k}-N{n}-d{depth:02d}'


def execute(args, stdout, stderr, timeout):
    with stdout.open('w') as out, stderr.open('w') as err:
        process = subprocess.Popen(args, stdout=out, stderr=err, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return 124


def make_report(output, summary):
    rows = summary['results']
    headers = ['l', 'k', 'N', 'depth', 'security_bits', 'status', 'minimum_recommended_N',
               'decrypt_max_error', 'multiply_max_error', 'depth_max_error',
               'precision_target_bits', 'strict_inverse_scale_passed', 'strict_inverse_scale_total', 'elapsed_seconds', 'reason']
    operations = sorted({op for r in rows for op in r.get('timings', {})})
    write_csv(output / 'summary.csv', headers + [op + '_mean_ms' for op in operations],
              [[r.get(key, '') for key in headers] + [r.get('timings', {}).get(op, {}).get('mean_ms', '') for op in operations] for r in rows])
    write_csv(output / 'timings.csv', ['case_id', 'l', 'k', 'N', 'depth', 'operation', 'samples',
              'mean_ms', 'median_ms', 'min_ms', 'max_ms', 'stddev_sample_ms', 'p95_nearest_rank_ms'],
              [[r['case_id'], r['l'], r['k'], r['N'], r['depth'], op, len(t['samples_ms'])] +
               [t[key] for key in ('mean_ms', 'median_ms', 'min_ms', 'max_ms', 'stddev_sample_ms', 'p95_nearest_rank_ms')]
               for r in rows for op, t in r.get('timings', {}).items()])
    status = {'passed': '通过：正确性及计时完成', 'security_rejected': 'OpenFHE 安全参数检查拒绝',
              'preflight_failed': '参数生成异常', 'experiment_failed': '正确性或运行失败',
              'verification_failed': '独立复算失败', 'timeout': '超时'}
    body = []
    for r in rows:
        error = r.get('depth_max_error')
        ms = r.get('timings', {}).get('depth_square_circuit', {}).get('mean_ms')
        body.append('<tr>' + ''.join(f'<td>{html.escape(str(x))}</td>' for x in
            [r['l'], r['k'], r['N'], r['depth'], status[r['status']], r.get('minimum_recommended_N', '—'),
             f'{error:.3e}' if error is not None else '未执行', f'{ms:.3f}' if ms is not None else '未执行']) +
            f'<td><a href="cases/{r["case_id"]}/result.json">结果</a> · <a href="cases/{r["case_id"]}/requested.conf">配置</a></td></tr>')
    counts = summary['counts']
    machine = summary['environment']
    text = f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>MLWR 60 组参数测试</title>
<style>body{{font:16px/1.65 system-ui,sans-serif;max-width:1450px;margin:32px auto;padding:0 20px;color:#171717}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{border:1px solid #ccc;padding:8px;text-align:left}}th{{background:#eee}}a{{color:#1449a0}}code{{background:#eee;padding:2px 5px}}.numbers{{font-size:22px;font-weight:600}}small{{color:#555}}</style>
<h1>MLWR：60 组参数测试结果</h1><p class="numbers">已完成 {len(rows)}/60 组；通过 {counts.get('passed',0)} 组；安全参数检查拒绝 {counts.get('security_rejected',0)} 组；其他失败 {sum(v for k,v in counts.items() if k not in ('passed','security_rejected'))} 组。</p>
<p>固定 security_bits=128、l=2；k∈{{2,3}}，N∈{{4096,8192,16384}}，depth=1–10。其余配置保持默认：slots=8、scale_bits=50、first_mod_bits=60、单 digit HYBRID；每组 {summary['base_parameters']['key_trials']} 把独立新密钥、每把 3 类消息；每项预热 {summary['base_parameters']['warmups']} 次、正式采样 {summary['base_parameters']['samples']} 次；目标误差 ≤ 2⁻²⁰。</p>
<p>环境：{html.escape(machine['system'] + ' / ' + machine.get('cpu', machine['architecture']))}。不同机器的耗时分别报告，不混合计算。代码提交：<code>{summary['source_commit']}</code>。</p>
<p>通过组完成加解密、一次乘法、张量积恒等式及系数误差检查，并实际执行 depth 层连续平方（每层：张量积→重线性化→重缩放），逐层解密与明文 x^(2^层数) 比较。深度电路使用幅度≤1 的实数、单位圆复数和随机消息。它验证这三类测试电路，不代表任意同深度电路。</p>
<p>计时包含密钥生成、重线性化密钥、旋转密钥、编码、加密、解密、准备、加法、旋转、乘法三阶段及合计，以及完整深度电路。正确性检查先于计时；解密验证不计入乘法和深度电路时间。深度电路时间从准备后的密文开始，含每层乘法和重缩放，不含初始准备及密钥生成。</p>
<p>被拒绝组也逐一运行并保留 OpenFHE 原始错误。其正确性与耗时为空，不能写成 0 或“通过”。没有增大用户指定的 N，也没有关闭安全检查。128 是 OpenFHE classic RLWE 参数表标签，本研究 MLWR 构造仍未完成安全证明；下表建议 N 只针对当前 OpenFHE 配置。</p>
<p><a href="summary.csv">60 组汇总 CSV</a> · <a href="timings.csv">各阶段完整计时 CSV</a> · <a href="summary.json">完整索引 JSON</a>。每组目录包含配置、原始日志；通过组另有 experiment.json、逐槽误差、各层误差、实际模数与计时原始样本。</p>
<table><thead><tr><th>l</th><th>k</th><th>N</th><th>深度</th><th>结果</th><th>建议最低 N</th><th>逐层最大误差</th><th>完整电路均值/ms</th><th>依据</th></tr></thead><tbody>{''.join(body)}</tbody></table>
<p><small>生成时间 {summary['completed_utc']}；实现 SHA-256 {summary['source_identity']['sha256']}。1/Δ 的严格比较另列于 CSV 和每组原始数据中，不以 20 位目标代替。</small></p></html>'''
    (output / 'report.html').write_text(text, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--samples', type=int, default=15)
    parser.add_argument('--warmups', type=int, default=2)
    parser.add_argument('--key-trials', type=int, default=3)
    parser.add_argument('--timeout', type=int, default=1800, help='Seconds per accepted configuration')
    args = parser.parse_args()
    if not (3 <= args.samples <= 1000 and 1 <= args.warmups <= 100 and 1 <= args.key_trials <= 100 and args.timeout > 0):
        parser.error('Invalid repetitions or timeout')
    root = Path(__file__).resolve().parents[1]
    executable = args.executable.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error('Output must be new or empty; do not mix runs or overwrite evidence')
    output.mkdir(parents=True, exist_ok=True)
    base = {}
    for line in (root / 'configs/default.conf').read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            key, value = (x.strip() for x in line.split('=', 1))
            base[key] = float(value) if key == 'message_bound' else int(value)
    base.update(security_bits=128, l=2, samples=args.samples, warmups=args.warmups, key_trials=args.key_trials)
    summary = {'schema_version': 1, 'started_utc': datetime.now(timezone.utc).isoformat(),
               'source_commit': command('git', '-C', str(root), 'rev-parse', 'HEAD'),
               'source_identity': source_identity(root), 'environment': environment(executable),
               'base_parameters': base, 'expected_cases': len(GRID), 'results': [],
               'runner_sha256': {name: digest(root / 'scripts' / name) for name in
                   ('run_parameter_grid.py', 'run_experiment.py', 'verify_experiment.py', 'verify_parameter_grid.py')}}
    (output / 'run-metadata.json').write_text(json.dumps(summary, indent=2) + '\n')
    for index, (l, k, n, depth) in enumerate(GRID, 1):
        label = case_id(l, k, n, depth)
        folder = output / 'cases' / label
        folder.mkdir(parents=True)
        config = dict(base, l=l, k=k, N=n, depth=depth)
        config_path = folder / 'requested.conf'
        config_path.write_text(''.join(f'{key} = {value}\n' for key, value in config.items()))
        result = {'case_id': label, 'l': l, 'k': k, 'N': n, 'depth': depth, 'security_bits': 128,
                  'requested_parameters': config, 'status': 'preflight_failed', 'reason': ''}
        started = time.monotonic()
        preflight = execute([str(executable), '--config', str(config_path), '--print-parameters'],
                            folder / 'preflight.json', folder / 'preflight.log', 120)
        result['preflight_exit_code'] = preflight
        error = (folder / 'preflight.log').read_text()
        match = SECURITY_ERROR.search(error)
        if preflight == 124:
            result.update(status='timeout', reason='Parameter generation timed out')
        elif preflight != 0:
            if preflight == 1 and match and int(match[1]) == n and int(match[2]) > n:
                result.update(status='security_rejected', minimum_recommended_N=int(match[2]), reason=match[0])
            else:
                result['reason'] = error.strip()
        else:
            try:
                profile = json.loads((folder / 'preflight.json').read_text())
                assert profile['requested_parameters'] == config
                assert profile['profile']['ring_dimension'] == n and profile['profile']['depth'] == depth
                assert profile['profile']['rlwe_security_table'] == 'HEStd_128_classic'
                code = execute([sys.executable, str(root / 'scripts/run_experiment.py'), str(folder), str(executable),
                                '--config', str(config_path)], folder / 'record.stdout.log', folder / 'record.stderr.log', args.timeout)
                result['experiment_exit_code'] = code
                if code != 0:
                    result.update(status='timeout' if code == 124 else 'experiment_failed',
                                  reason=(folder / 'record.stderr.log').read_text()[-3000:])
                else:
                    result['status'] = 'verification_failed'
                    report = verify(folder / 'experiment.json')
                    assert report['source_identity'] == summary['source_identity']
                    assert report['requested_parameters'] == config
                    metrics = [m for case in report['correctness'] for m in case['metrics']]
                    deep = [m for case in report['correctness'] for m in case['depth_circuit']['metrics']]
                    result.update(status='passed', timings=report['timings'],
                        decrypt_max_error=max(m['max_absolute_error'] for m in metrics if m['operation'].startswith('decrypt_')),
                        multiply_max_error=max(m['max_absolute_error'] for m in metrics if m['operation'] == 'multiply_after_rescale'),
                        depth_max_error=max(m['max_absolute_error'] for m in deep),
                        precision_target_bits=report['protocol']['precision_target_bits'],
                        strict_inverse_scale_passed=sum(m['passes_inverse_scale'] for m in metrics + deep),
                        strict_inverse_scale_total=len(metrics) + len(deep))
            except (AssertionError, ValueError, KeyError, OSError) as error:
                result['reason'] = f'{type(error).__name__}: {error}'
        result['elapsed_seconds'] = time.monotonic() - started
        result['evidence_sha256'] = {str(p.relative_to(folder)): digest(p) for p in sorted(folder.iterdir()) if p.is_file()}
        (folder / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        summary['results'].append(result)
        print(f'[{index}/60] {label}: {result["status"]}', flush=True)
    assert source_identity(root) == summary['source_identity'], 'Source changed during grid run'
    assert digest(executable) == summary['environment']['executable_sha256'], 'Executable changed during grid run'
    summary['completed_utc'] = datetime.now(timezone.utc).isoformat()
    summary['counts'] = dict(Counter(r['status'] for r in summary['results']))
    summary['all_combinations_passed'] = summary['counts'].get('passed') == len(GRID)
    summary['all_combinations_attempted'] = True
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    make_report(output, summary)
    print(json.dumps(summary['counts']), flush=True)
    return 0 if all(r['status'] in ('passed', 'security_rejected') for r in summary['results']) else 1


if __name__ == '__main__':
    sys.exit(main())
