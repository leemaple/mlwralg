"""Run bounded bootstrap trials, preserve failures, and verify full-slot results."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time

from run_experiment import command, digest, environment, source_identity, write_csv
from verify_bootstrap import verify


def parse_arguments(argv=None):
    # Unknown options belong to the C++ executable. In particular --k must not
    # abbreviate --key-trials and silently replace the number of fresh keys.
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('output',type=Path);parser.add_argument('executable',type=Path)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--key-trials',type=int,default=3)
    parser.add_argument('--timeout',type=int,default=360)
    parser.add_argument('--experiment-class',choices=['diagnostic','qualification'],default='diagnostic')
    args,extra=parser.parse_known_args(argv)
    if not 1<=args.key_trials<=10 or args.timeout<1:parser.error('Invalid repetitions/timeout')
    if args.experiment_class=='qualification':
        if args.key_trials<3:parser.error('Qualification requires at least three fresh keys per family')
        if '--refresh-probe' in extra or re.search(r'^\s*refresh[_-]probe\s*=\s*1',args.config.read_text(),re.M):
            parser.error('Refresh-only probes cannot qualify a continued circuit')
    if args.output.exists() and any(args.output.iterdir()):parser.error('Use a new evidence directory')
    return args,extra


def main():
    args,extra=parse_arguments()
    args.output.mkdir(parents=True,exist_ok=True)
    root=Path(__file__).resolve().parents[1];binary=args.executable.resolve(strict=True)
    identity=source_identity(root);binary_hash=digest(binary)
    manifest=None;manifest_path=None
    cache=binary.parent/'CMakeCache.txt'
    if cache.exists():
        entries=dict(line.split('=',1) for line in cache.read_text().splitlines()
                     if '=' in line and not line.startswith(('#','//')))
        location=next((v for k,v in entries.items() if k.startswith('OpenFHE_DIR:')),None)
        if location:
            manifest_path=Path(location).resolve().parents[1]/'mlwr-port-manifest.json'
            if manifest_path.exists():manifest=json.loads(manifest_path.read_text())
    config=args.output/'requested.conf';config.write_bytes(args.config.read_bytes())
    metadata={'source_commit':command('git','-C',str(root),'rev-parse','HEAD'),
        'source_identity':identity,'environment':environment(binary),
        'experiment_class':args.experiment_class,'started_utc':datetime.now(timezone.utc).isoformat(),
        'key_trials_per_family':args.key_trials,'expected_runs':3*args.key_trials,
        'openfhe_port_manifest':manifest,
        'openfhe_port_manifest_sha256':digest(manifest_path) if manifest else None,
        'runner_sha256':{f:digest(root/'scripts'/f) for f in ['run_bootstrap.py','verify_bootstrap.py']},'results':[]}
    for trial in range(args.key_trials):
        for family in range(3):
            folder=args.output/f'trial{trial+1}-family{family}';folder.mkdir()
            argv=[str(binary),'--config',str(config.resolve()),*extra,'--family',str(family)]
            (folder/'command.json').write_text(json.dumps(argv,indent=2))
            start=time.monotonic()
            with (folder/'output.json').open('w') as out,(folder/'stderr.log').open('w') as err:
                try:code=subprocess.run(argv,stdout=out,stderr=err,timeout=args.timeout).returncode
                except subprocess.TimeoutExpired:code=124
            row={'case':folder.name,'trial':trial+1,'family':family,'exit_code':code,
                 'elapsed_seconds':time.monotonic()-start,'status':'timeout' if code==124 else 'runtime_failed'}
            if code in (0,2):
                try:
                    oracle=verify(folder/'output.json')
                    report=json.loads((folder/'output.json').read_text())
                    if 'port_helper_sha256' in report['profile']:
                        assert manifest
                        assert report['profile']['port_helper_sha256']==manifest['helper_sha256']==digest(root/'patches/openfhe-p03-small.inc')
                        assert report['profile']['patched_fhe_sha256']==manifest['patched_fhe_sha256']
                        assert manifest['patcher_sha256']==digest(root/'scripts/patch_openfhe_sparse.py')
                    if args.experiment_class=='qualification':
                        assert report['validation_scope']=='two_refresh_continuation'
                        assert report['circuit_depth']>0 and oracle['depth']==report['circuit_depth']
                        assert oracle['refreshes']>=2
                    assert (code==0)==oracle['accepted']
                    row.update(status='passed' if oracle['accepted'] else 'precision_failed',oracle=oracle,
                               timings_ms=report['timings_ms'],profile=report['profile'])
                    (folder/'oracle.json').write_text(json.dumps(oracle,indent=2))
                except (AssertionError,ValueError,KeyError) as e:
                    row.update(status='verification_failed',error=repr(e))
            log=(folder/'stderr.log').read_text()
            native={name:[1000*float(x) for x in re.findall(pattern,log)] for name,pattern in {
                'cts_ms':r'Encoding time: ([\d.]+) s',
                'evalmod_ms':r'Approximate modular reduction time: ([\d.]+) s',
                'stc_ms':r'Decoding time: ([\d.]+) s'}.items()}
            row['native_stage_samples_ms']=native
            row['files_sha256']={p.name:digest(p) for p in folder.iterdir() if p.is_file()}
            (folder/'result.json').write_text(json.dumps(row,indent=2))
            metadata['results'].append(row)
            print(folder.name,row['status'],flush=True)
    assert source_identity(root)==identity,'Source changed during run'
    assert digest(binary)==binary_hash,'Executable changed during run'
    metadata['completed_utc']=datetime.now(timezone.utc).isoformat()
    metadata['all_passed']=all(r['status']=='passed' for r in metadata['results'])
    (args.output/'summary.json').write_text(json.dumps(metadata,indent=2))
    write_csv(args.output/'summary.csv',['case','status','depth','refreshes','max_error','evaluator_total_ms','elapsed_seconds'],
        [[r['case'],r['status'],*[r.get('oracle',{}).get(x,'') for x in ['depth','refreshes','max_error']],
          r.get('timings_ms',{}).get('evaluator_total_ms',''),r['elapsed_seconds']] for r in metadata['results']])
    return 0 if metadata['all_passed'] else 1


if __name__=='__main__':raise SystemExit(main())
