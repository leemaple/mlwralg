"""Recompute the declared plaintext circuit from exact binary input values.

This offline audit uses 140-decimal-digit arithmetic. It neither evaluates
ciphertexts nor reuses a previous decrypted value as the plaintext reference.
"""
import argparse
import csv
from decimal import Decimal,localcontext
import hashlib
import json
from pathlib import Path

D=Decimal

def pair(values):return tuple(D.from_float(float(x)) for x in values)
def square(z):return z[0]*z[0]-z[1]*z[1],2*z[0]*z[1]
def multiply(a,b):return a[0]*b[0]-a[1]*b[1],a[0]*b[1]+a[1]*b[0]
def distance(a,b):return ((a[0]-b[0])**2+(a[1]-b[1])**2).sqrt()

def audit(path):
 report=json.loads(path.read_text());rows=[]
 with localcontext() as ctx:
  ctx.prec=140
  tolerance=D(2)**(-report['protocol']['precision_target_bits'])
  for case in report['correctness']:
   original={m['operation']:m for m in case['metrics']}
   left=[pair(x) for x in original['decrypt_fresh_a']['expected']]
   right=[pair(x) for x in original['decrypt_fresh_b']['expected']]
   product=[multiply(a,b) for a,b in zip(left,right)]
   for metric in case['metrics']:
    name=metric['operation']
    expected=product if name.startswith('multiply_') else right if name.endswith('_b') else left
    error=max(distance(pair(a),b) for a,b in zip(metric['actual'],expected))
    reference_gap=max(distance(pair(a),b) for a,b in zip(metric['expected'],expected))
    assert error<=tolerance,(path,case['trial'],case['case'],name,str(error))
    assert reference_gap<D('1e-11'),('One-operation plaintext reference unexpectedly inaccurate',path,name,str(reference_gap))
    rows.append({'file':str(path),'trial':case['trial'],'case':case['case'],'layer':metric['level'],'operation':name,
      'max_error_decimal':str(error),'native_reference_gap':str(reference_gap),
      'target':str(tolerance),'passes_target':True,
      'passes_inverse_scale':error<=1/D.from_float(metric['scale'])})
   circuit=case['depth_circuit'];expected=[pair(x) for x in circuit['input']]
   for layer,metric in enumerate(circuit['metrics'],1):
    expected=[square(x) for x in expected]
    error=max(distance(pair(a),b) for a,b in zip(metric['actual'],expected))
    reference_gap=max(distance(pair(a),b) for a,b in zip(metric['expected'],expected))
    assert error<=tolerance,(path,case['trial'],case['case'],layer,str(error))
    assert reference_gap<D('1e-11'),('Double plaintext reference unexpectedly inaccurate',path,str(reference_gap))
    rows.append({'file':str(path),'trial':case['trial'],'case':case['case'],'layer':layer,'operation':'depth_square',
      'max_error_decimal':str(error),'native_reference_gap':str(reference_gap),
      'target':str(tolerance),'passes_target':True,
      'passes_inverse_scale':error<=1/D.from_float(metric['scale'])})
   if 'lowest_rotation_metric' in circuit:
    rotation=circuit['lowest_rotation_metric'];steps=report['protocol']['rotation_steps']%len(expected)
    shifted=expected[steps:]+expected[:steps]
    error=max(distance(pair(a),b) for a,b in zip(rotation['actual'],shifted))
    assert error<=tolerance,(path,'lowest rotation',str(error))
    rows.append({'file':str(path),'trial':case['trial'],'case':case['case'],'layer':report['profile']['depth'],
      'operation':'rotate_lowest_level','max_error_decimal':str(error),'native_reference_gap':'',
      'target':str(tolerance),'passes_target':True,
      'passes_inverse_scale':error<=1/D.from_float(rotation['scale'])})
 return rows


def main():
 parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);parser.add_argument('inputs',nargs='+',type=Path)
 args=parser.parse_args();paths=[]
 for p in args.inputs:
  paths.extend(sorted(p.glob('cases/*/experiment.json')) if p.is_dir() else [p])
 assert paths,'No completed experiments found'
 rows=[row for p in paths for row in audit(p)]
 args.output.mkdir(parents=True,exist_ok=True)
 with (args.output/'decimal-oracle.csv').open('w',encoding='utf-8-sig',newline='') as f:
  writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
 with localcontext() as ctx:
  ctx.prec=140
  summary={'reports':len(paths),'observations':len(rows),'precision_decimal_digits':140,
    'max_absolute_error':str(max(D(r['max_error_decimal']) for r in rows)),
    'max_native_reference_gap':str(max(D(r['native_reference_gap'] or '0') for r in rows)),
    'all_pass':all(r['passes_target'] for r in rows),'inverse_scale_passes':sum(r['passes_inverse_scale'] for r in rows),
    'input_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}
 (args.output/'decimal-oracle-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({k:v for k,v in summary.items() if k!='input_sha256'},ensure_ascii=False))


if __name__=='__main__':main()
