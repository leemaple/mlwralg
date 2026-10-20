"""Admit three matched shards as a nine-run bootstrap qualification.

A shard is only one fresh process per family for each backend. It cannot qualify
alone. The merge preserves raw files, checks all 12 unique matrix cells and uses
within-runner native/P03 ratios, never ratios between unrelated runner models.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
from statistics import median


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(2**20),b''):h.update(block)
    return h.hexdigest()


def read(path):return json.loads(path.read_text())


def validate(folder,k,slots,trial):
    assert k in (2,3) and slots in (8,64) and trial in (1,2,3)
    summaries={};hashes=[]
    for name in ('native','p03'):
        root=folder/('bootstrap-'+name);summary=read(root/'summary.json')
        assert summary['key_trials_per_family']==1 and summary['expected_runs']==3
        assert summary['all_passed'] and len(summary['results'])==3
        assert {(r['trial'],r['family'])for r in summary['results']}=={(1,f)for f in (0,1,2)}
        for row in summary['results']:
            assert row['status']=='passed' and row['oracle']['accepted']
            assert row['case']==f'trial1-family{row["family"]}'
            assert all(Path(name).name==name for name in row['files_sha256'])
            case=root/row['case']
            for file,sha in row['files_sha256'].items():assert digest(case/file)==sha,(case,file)
            r=read(case/'output.json');p=r['profile']
            # Bind matrix labels to the actual native output. This would reject
            # the earlier argparse --k/--key-trials abbreviation counterexample.
            assert (r['l'],r['k'],p['N'],p['slots'])==(2,k,65536,slots)
            assert r['family']==row['family'] and r['all_checks_passed']
            assert r['validation_scope']=='two_refresh_continuation'
            assert r['multiplication_backend']=='folded_rlwe_hybrid'
            assert r['circuit_depth']==row['oracle']['depth']==40 and r['refresh_count']==8
            assert r['iterations']==2 and r['correction_precision']==12 and r['precision_bits']==20
            assert p['security_bits']==128 and p['secret_distribution']=='UNIFORM_TERNARY'
            assert p['checked_public_bits']==1677 and p['total_depth']==24 and p['project_repeated']
            assert p['transform']==('OpenFHE_native'if name=='native'else'P03_small_repeated')
            assert len(r['records'])==48 and row['oracle']['checked_slots']==50*(65536//2)
            assert len(r['fresh_decoded'])==len(r['fold_decoded'])==65536//2
            assert all(len(x['decoded'])==65536//2 for x in r['records'])
            assert 0<=r['max_error']<=2**-20
            assert abs(float(row['oracle']['max_error'])-r['max_error'])<1e-12
            assert all(math.isfinite(v) and v>=0 for v in r['timings_ms'].values())
            manifest=summary['openfhe_port_manifest'];assert manifest
            assert p['port_helper_sha256']==manifest['helper_sha256']==summary['source_identity']['files']['patches/openfhe-p03-small.inc']
            assert p['patched_fhe_sha256']==manifest['patched_fhe_sha256']=='80339607cba01ab4a2af082112876729042e63557f20ea1c5b045f886ab51b5b'
            hashes.append(row['files_sha256']['output.json'])
        summaries[name]=summary
    a,b=summaries.values()
    assert a['source_identity']==b['source_identity'] and a['source_commit']==b['source_commit']
    assert a['environment']==b['environment'],'Pair must use the same runner and exact binary'
    assert len(set(hashes))==6,'Repeated identical raw output is not a fresh-key run'
    times={name:median(s['results'][i]['timings_ms']['evaluator_total_ms'] for i in range(3))for name,s in summaries.items()}
    admission={'stage':'matched_shard_not_standalone_qualification','k':k,'slots':slots,'trial':trial,
        'runs':6,'source_identity':a['source_identity'],'source_commit':a['source_commit'],
        'environment':a['environment'],'summary_sha256':{name:digest(folder/('bootstrap-'+name)/'summary.json')for name in summaries},
        'output_sha256':hashes,'native_median_ms':times['native'],'p03_median_ms':times['p03'],
        'time_ratio':times['p03']/times['native'],'checker_sha256':digest(Path(__file__))}
    return admission,summaries


def copy_tree(src,dst):
    def link_or_copy(a,b):
        try:os.link(a,b)
        except OSError:shutil.copy2(a,b)
    shutil.copytree(src,dst,copy_function=link_or_copy)


def merge(output,inputs):
    assert not output.exists() or not any(output.iterdir()),'Use a fresh merge directory'
    cells={};all_hashes=[]
    for part in inputs:
        matches=list(part.glob('**/shard-admission.json'));assert len(matches)==1,(part,matches)
        path=matches[0];stored=read(path)
        checked,summaries=validate(path.parent,stored['k'],stored['slots'],stored['trial'])
        assert stored==checked,'Shard admission does not match its preserved observations'
        key=stored['k'],stored['slots'],stored['trial'];assert key not in cells
        cells[key]=(path.parent,stored,summaries);all_hashes+=stored['output_sha256']
    assert set(cells)=={(k,s,t)for k in (2,3)for s in (8,64)for t in (1,2,3)},'All12shards are required'
    assert len(set(all_hashes))==72,'Duplicate raw cases cannot count as independent trials'
    first=next(iter(cells.values()))[1]
    assert all(v[1]['source_identity']==first['source_identity'] and v[1]['source_commit']==first['source_commit']for v in cells.values())
    output.mkdir(parents=True,exist_ok=True);pairs=[]
    for k in (2,3):
        for slots in (8,64):
            group=output/f'bootstrap-k{k}-slots{slots}'
            group.mkdir()
            admissions=[cells[k,slots,t][1]for t in (1,2,3)]
            comparison={'k':k,'slots':slots,'method':'median of3 within-runner ratios; each ratio uses medians over3 message families',
                'time_ratios':[x['time_ratio']for x in admissions],
                'median_time_ratio':median(x['time_ratio']for x in admissions),'runners':admissions}
            (group/'matched-comparison.json').write_text(json.dumps(comparison,indent=2))
            pairs.append(comparison)
            for name in ('native','p03'):
                target=group/('bootstrap-'+name);target.mkdir()
                original=cells[k,slots,1][2][name]
                summary={key:value for key,value in original.items()if key not in ('results','environment','started_utc','completed_utc')}
                summary.update(experiment_class='qualification',admission_method='three independently validated matched shards',
                    key_trials_per_family=3,expected_runs=9,results=[],runner_environments={},shard_sources={},
                    environment={'scope':'three matched runners; use runner_environments for each case'},
                    merge_checker_sha256=digest(Path(__file__)),all_passed=True)
                shutil.copy2(cells[k,slots,1][0]/('bootstrap-'+name)/'requested.conf',target/'requested.conf')
                for trial in (1,2,3):
                    folder,admission,part=cells[k,slots,trial];part=part[name];runner=f'shard{trial}'
                    summary['runner_environments'][runner]=admission['environment']
                    summary['shard_sources'][runner]={'summary_sha256':admission['summary_sha256'][name],'admission':admission}
                    for row in part['results']:
                        index=dict(row,source_case=row['case'],source_trial=row['trial'],trial=trial,
                                   case=f'shard{trial}-{row["case"]}',runner_key=runner)
                        copy_tree(folder/('bootstrap-'+name)/row['case'],target/index['case'])
                        # Raw result.json remains byte-for-byte unchanged. Only
                        # the external index maps the shard's local trial1 to a
                        # global trial number; the source mapping is explicit.
                        summary['results'].append(index)
                (target/'summary.json').write_text(json.dumps(summary,indent=2))
                import csv
                with (target/'summary.csv').open('w',encoding='utf-8-sig',newline='')as f:
                    w=csv.writer(f);w.writerow(['case','runner','status','depth','refreshes','max_error','evaluator_total_ms'])
                    for r in summary['results']:w.writerow([r['case'],r['runner_key'],r['status'],r['oracle']['depth'],r['oracle']['refreshes'],r['oracle']['max_error'],r['timings_ms']['evaluator_total_ms']])
    (output/'qualification-admission.json').write_text(json.dumps({'source_identity':first['source_identity'],
        'source_commit':first['source_commit'],'admitted_runs':72,'shards':12,'all_passed':True,'matched_comparisons':pairs},indent=2))
    print('Admitted72runs: k2/3 x slots8/64 x native/P03 x3fresh keys per family x3families')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check-shard',type=Path);p.add_argument('--k',type=int);p.add_argument('--slots',type=int);p.add_argument('--trial',type=int)
    p.add_argument('output',type=Path,nargs='?');p.add_argument('inputs',type=Path,nargs='*');a=p.parse_args()
    if a.check_shard:
        if None in (a.k,a.slots,a.trial):p.error('k, slots and trial are required')
        result,_=validate(a.check_shard,a.k,a.slots,a.trial)
        (a.check_shard/'shard-admission.json').write_text(json.dumps(result,indent=2));print('Matched shard validated; it does not qualify alone')
    else:
        if a.output is None or not a.inputs:p.error('Output and all12artifact directories are required')
        merge(a.output,a.inputs)
if __name__=='__main__':main()
