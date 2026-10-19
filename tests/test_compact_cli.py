"""Configuration priority and explicit modulus-budget gates for compact mode."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
binary=str(Path(sys.argv[1]).resolve());root=Path(__file__).resolve().parents[1];checks=0

def run(*args,fail=False):
 global checks
 r=subprocess.run([binary,*map(str,args)],capture_output=True,text=True)
 assert bool(r.returncode)==fail,(args,r.stdout,r.stderr)
 checks+=1
 return r

r=json.loads(run('--config',root/'configs/compact/n4096.conf','--print-parameters').stdout)
assert r['schema_version']==4 and r['profile']['checked_public_modulus_bits']<=109
assert r['requested_parameters']['compact']==1 and r['profile']['ring_dimension']==4096
with tempfile.TemporaryDirectory() as directory:
 p=Path(directory)/'参数.conf';p.write_text((root/'configs/compact/n4096.conf').read_text().replace('compact = 1','compact = 0'))
 result=json.loads(run('--compact','--config',p,'--print-parameters').stdout)
 assert result['requested_parameters']['compact']==1
for options in [('--gadget-bits','3'),('--gadget-bits','31'),('--divisor-bits','15'),
                ('--public-extra-bits','15'),('--n','0'),('--compact','--compact')]:
 run('--config',root/'configs/compact/n4096.conf',*options,'--print-parameters',fail=True)
run('--config',root/'configs/compact/n8192.conf','--depth','5','--print-parameters',fail=True)
print(json.dumps({'checks':checks,'passed':True}))
