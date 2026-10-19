"""Exercise user-facing configuration precedence, validation, and metadata."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

demo = str(Path(sys.argv[1]).resolve())
root = Path(__file__).resolve().parents[1]
checks = 0


def run(*args, fail=False):
    global checks
    result = subprocess.run([demo, *map(str, args)], capture_output=True, text=True)
    assert (result.returncode != 0) == fail, (args, result.stdout, result.stderr)
    checks += 1
    return result


default = json.loads(run('--config', root / 'configs/default.conf', '--print-parameters').stdout)
fixture = json.loads((root / 'tests/fixtures/parameters.json').read_text())
assert default['profile'] == fixture['profile'], 'Default numerical profile changed'
run('--help')
deep = json.loads(run('--depth', 10, '--n', 0, '--print-parameters').stdout)
assert deep['profile']['depth'] == 10 and deep['profile']['rlwe_security_table'] == 'HEStd_128_classic'
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / '参数 配置.conf'
    path.write_text('\ufeff# 中文注释\r\nl = 3\r\nk = 1\r\nN = 65536\r\nslots = 16\r\n'
                    'depth = 1\r\nscale_bits = 48\r\nsecurity_bits = 192\r\n'
                    'message_bound = 0.5\r\nsmudge_bound = 1024\r\nrotation_steps = -3\r\ninitial_scale_bits = 70\r\n')
    resolved = json.loads(run('--l', 1, '--config', path, '--k', 3, '--print-parameters').stdout)
    request = resolved['requested_parameters']
    assert request['l'] == 1 and request['k'] == 3 and request['rotation_steps'] == -3
    assert request['message_bound'] == .5 and request['smudge_bound'] == 1024
    assert resolved['profile']['ring_dimension'] == 65536 and resolved['profile']['slots'] == 16
    assert resolved['profile']['rlwe_security_table'] == 'HEStd_192_classic'
    # These actually execute decoding, multiplication and rotation with the
    # nondefault bound, smudging and negative shift, beyond parser-only checks.
    run('--config', path, '--l', 1, '--k', 1)
    for text in ('l=2\nl=3', 'typo=1', 'l=2junk', 'k=-1', 'N=32768\nn=65536', 'k 2'):
        path.write_text(text)
        run('--config', path, '--print-parameters', fail=True)
for args in [('--l', 0), ('--k', 9), ('--n', 1000), ('--n', 1024),
             ('--slots', 3), ('--n', 16384, '--slots', 16384), ('--depth', 0), ('--depth', 11),
             ('--scale-bits', 40), ('--scale-bits', 60), ('--first-mod-bits', 50),
             ('--samples', 2), ('--warmups', 0), ('--security-bits', 0),
             ('--precision-bits', 51), ('--key-trials', 0), ('--message-bound', 'nan'),
             ('--message-bound', 0), ('--message-bound', '2junk'), ('--smudge-bound', 1073741825),
             ('--initial-scale-bits', 39), ('--initial-scale-bits', 101), ('--rotation-steps', -65537), ('--k', '2.5'), ('--k', '4294967296'),
             ('--config', ''), ('--config', 'missing-file.conf'), ('--l', 1, '--l', 2), ('--unknown', 1)]:
    run(*args, '--print-parameters', fail=True)
run('--k', fail=True)
print(json.dumps({'cli_checks': checks, 'passed': True}))
