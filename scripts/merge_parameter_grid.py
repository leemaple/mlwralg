"""Assemble disjoint GitHub jobs and audit complete 60-case coverage."""
from collections import Counter
import json
from pathlib import Path
import shutil
import sys
from run_parameter_grid import GRID,make_report
from run_experiment import command,digest
from verify_parameter_grid import check


def main():
    output=Path(sys.argv[1]);sources=[Path(p) for p in sys.argv[2:]]
    assert len(sources) in (6,60),'Require all six k/N groups or all sixty single-case jobs'
    assert not output.exists() or not any(output.iterdir()),'New output directory required'
    output.mkdir(parents=True,exist_ok=True)
    summary=None;results=[];environments={}
    for source in sources:
        report=check(source,allow_subset=True)
        assert len(report['results'])==(1 if report['selection'].get('depth') else 10)
        key=f'k{report["selection"]["k"]}-N{report["selection"]["N"]}'
        if report['selection'].get('depth'):key+=f'-d{report["selection"]["depth"]}'
        assert key not in environments
        environments[key]=report['environment']
        if summary is None:
            summary=dict(report);summary['started_utc']=report['started_utc']
        else:
            for field in ('source_commit','source_identity','runner_sha256','base_parameters','compact','per_ring_parameters','optimized','depth_overrides'):
                assert report.get(field)==summary.get(field),field
            summary['started_utc']=min(summary['started_utc'],report['started_utc'])
        summary['completed_utc']=max(summary.get('completed_utc',''),report['completed_utc'])
        for row in report['results']:
            dest=output/'cases'/row['case_id'];assert not dest.exists()
            shutil.copytree(source/'cases'/row['case_id'],dest)
            row=dict(row,runner_key=key);(dest/'result.json').write_text(json.dumps(row,indent=2)+'\n');results.append(row)
    order={g:i for i,g in enumerate(GRID)}
    assert len(results)==60 and len({r['case_id'] for r in results})==60
    results.sort(key=lambda r:order[(r['l'],r['k'],r['N'],r['depth'])])
    summary.update(results=results,selection={'k':None,'N':None,'depth':None},expected_cases=60,
        runner_environments=environments,counts=dict(Counter(r['status'] for r in results)),
        all_combinations_attempted=True,all_combinations_passed=all(r['status']=='passed' for r in results))
    summary['assembly_tool_commit']=command('git','-C',str(Path(__file__).resolve().parents[1]),'rev-parse','HEAD')
    summary['assembly_tools_sha256']={name:digest(Path(__file__).parent/name) for name in ('merge_parameter_grid.py','verify_parameter_grid.py','precision_failure.py')}
    summary['environment']=dict(summary['environment'],cpu=f'{len(sources)} isolated GitHub runners; exact CPU and binary identity are retained per case')
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    make_report(output,summary);check(output)


if __name__=='__main__':main()
