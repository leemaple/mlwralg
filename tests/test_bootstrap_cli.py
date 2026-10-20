"""Strict parsing and small-N rejection, without an expensive bootstrap run."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from run_bootstrap import parse_arguments

binary=str(Path(sys.argv[1]).resolve())
checks=0
def run(*args,fail=False):
    global checks
    r=subprocess.run([binary,*map(str,args)],capture_output=True,text=True,timeout=30)
    assert bool(r.returncode)==fail,(args,r.stdout,r.stderr)
    checks+=1
    return r
for args in [('--n','-1'),('--k','2x'),('--paper-sparse','2'),('--n','8192'),
             ('--l','0'),('--n','65536','--n','65536'),('--iterations','2'),
             ('--flexible-scaling','0'),('--unknown','1'),('--n',' 65536')]:
    run(*args,'--print-parameters',fail=True)
with tempfile.TemporaryDirectory() as directory:
    p=Path(directory)/'参数.conf';p.write_text('N=65536\nslots=8\nscale_bits=55\nfirst_mod_bits=56\n')
    r=json.loads(run('--config',p,'--slots','16','--print-parameters').stdout)
    assert r['slots']==16 and r['security_bits']==128
    assert len(r['Q_primes'])==21 and r['checked_public_bits']<=1747
    p.write_text('N=65536\nN=65536\n')
    run('--config',p,'--print-parameters',fail=True)
    # Real regression: argparse's default prefix matching consumed --k as
    # --key-trials, rejecting k=2 or silently running k=2 when k=3 was requested.
    p.write_text('N=65536\n')
    for k in ('2','3'):
        for forwarded_first in (False,True):
            forwarded=['--k',k,'--slots','64','--paper-sparse','1','--circuit-depth','40']
            runner=['--key-trials','3','--experiment-class','qualification']
            argv=[str(Path(directory)/'evidence'),binary,'--config',str(p)]
            argv+=forwarded+runner if forwarded_first else runner+forwarded
            args,extra=parse_arguments(argv)
            assert args.key_trials==3 and extra==forwarded,(args,extra)
            checks+=1
print(json.dumps({'checks':checks,'passed':True}))
