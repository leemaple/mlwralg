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
run('--config',root/'configs/compact/n8192.conf','--symmetric-relinearization','2','--print-parameters',fail=True)
r=json.loads(run('--config',root/'configs/compact/n8192.conf','--symmetric-relinearization','1','--print-parameters').stdout)
assert r['profile']['symmetric_relinearization'] is True
assert r['requested_parameters']['symmetric_relinearization']==1
r=json.loads(run('--config',root/'configs/compact/n8192.conf','--depth','5','--scale-bits','27',
                 '--scale-log2','27.5','--first-mod-bits','46','--divisor-bits','16','--print-parameters').stdout)
assert r['requested_parameters']['scale_log2']==27.5
assert r['profile']['checked_public_modulus_bits']<=218
import math
assert all(abs(math.log2(int(p['prime']))-27.5)<.02 for p in r['profile']['ciphertext_basis'][1:-1])
for bad in ['nan','inf','-1','28.5']:
 run('--config',root/'configs/compact/n8192.conf','--scale-bits','27','--scale-log2',bad,'--print-parameters',fail=True)
r=json.loads(run('--config',root/'configs/compact/n8192.conf','--depth','5','--scale-bits','27',
 '--scale-log2','27.83','--first-mod-bits','46','--divisor-bits','16','--packed-public-key','1','--print-parameters').stdout)
assert r['profile']['packed_public_key'] is True and r['profile']['checked_public_modulus_bits']==218
run('--config',root/'configs/compact/n8192.conf','--packed-public-key','2','--print-parameters',fail=True)
print(json.dumps({'checks':checks,'passed':True}))
