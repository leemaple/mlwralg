"""Independently audit one immutable matched shard before publication.

The CI merge checker is frozen in its original artifacts. This additional gate
recomputes every full-slot oracle and derives timing ratios from the original
native output, binding them to the exact runner/verifier and GitHub job records.
It does not rerun encryption or alter any original observation.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from statistics import median
import zipfile

from merge_bootstrap_shards import digest, read, validate
from run_experiment import source_identity
from verify_bootstrap import verify


def audit(artifact, output, archive, run_metadata, artifacts_metadata, expected_commit):
    if not __debug__:
        raise RuntimeError('Run without -O: validation assertions must be enabled')
    assert not output.exists(), 'Use a fresh audit output file'
    assert not artifact.is_symlink()
    assert all(not p.is_symlink() for p in artifact.rglob('*')), 'Symbolic links are not admitted'
    matches = list(artifact.glob('**/shard-admission.json'))
    assert len(matches) == 1, matches
    admission_path = matches[0]
    stored = read(admission_path)
    k, slots, trial = (stored[x] for x in ('k', 'slots', 'trial'))
    root = admission_path.parent
    checked, summaries = validate(root, k, slots, trial)
    assert checked == stored, 'The frozen checker must reproduce its original admission'

    repo = Path(__file__).resolve().parents[1]
    expected_identity = source_identity(repo)
    expected_scripts = {name: digest(repo/'scripts'/name)
                        for name in ('run_bootstrap.py', 'verify_bootstrap.py')}
    state, artifacts = read(run_metadata), read(artifacts_metadata)
    assert state['headSha'] == expected_commit
    run_id = int(state['url'].rstrip('/').split('/')[-1])
    job_name = f'matched-shard ({k}, {slots}, {trial})'
    jobs = [j for j in state['jobs'] if j['name'] == job_name]
    assert len(jobs) == 1
    job = jobs[0]
    assert job['status'] == 'completed' and job['conclusion'] == 'success'
    paired = [s for s in job['steps']
              if s['name'] == 'Matched native and P03 samples on the same runner']
    assert len(paired) == 1 and paired[0]['conclusion'] == 'success'
    name = f'bootstrap-shard-k{k}-s{slots}-t{trial}'
    entries = [a for a in artifacts if a['name'] == name]
    assert len(entries) == 1 and not entries[0]['expired']
    attachment = entries[0]
    assert attachment['workflow_run']['id'] == run_id
    assert attachment['workflow_run']['head_sha'] == expected_commit
    # Bind the extracted files to GitHub's original archive, not merely to a
    # similarly named local directory or a copied metadata record.
    assert attachment['digest'].startswith('sha256:')
    archive_sha = digest(archive)
    assert archive_sha == attachment['digest'].split(':', 1)[1]
    archive_members = {}
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            rel = PurePosixPath(item.filename)
            assert not rel.is_absolute() and '..' not in rel.parts
            if item.is_dir():
                continue
            assert item.filename == rel.as_posix(), 'Noncanonical archive member path'
            assert item.filename not in archive_members
            h = hashlib.sha256()
            with z.open(item) as stream:
                for block in iter(lambda: stream.read(2**20), b''):
                    h.update(block)
            local = artifact.joinpath(*rel.parts)
            assert local.stat().st_size == item.file_size and digest(local) == h.hexdigest()
            archive_members[item.filename] = h.hexdigest()
    local_members = {p.relative_to(artifact).as_posix() for p in artifact.rglob('*') if p.is_file()}
    # The downloader adds only this separate receipt. Every file that the
    # checker or oracle may consume must belong to the verified archive.
    local_members.discard('artifact-download.json')
    assert local_members == set(archive_members), 'Unexpected or missing extracted files'

    cases, times, workloads = [], {}, {}
    for backend, summary in summaries.items():
        assert summary['source_commit'] == expected_commit
        assert summary['source_identity'] == expected_identity
        assert summary['runner_sha256'] == expected_scripts
        assert summary['openfhe_port_manifest']['patcher_sha256'] == digest(
            repo/'scripts/patch_openfhe_sparse.py')
        times[backend] = []
        for row in summary['results']:
            folder = root/('bootstrap-'+backend)/row['case']
            assert read(folder/'result.json') == row
            assert {'output.json', 'oracle.json', 'command.json', 'stderr.log'} <= set(row['files_sha256'])
            original = read(folder/'output.json')
            assert original['timings_ms'] == row['timings_ms']
            assert original['profile'] == row['profile']
            assert read(folder/'oracle.json') == row['oracle']
            workload = (original['input'], original['factor'], original['circuit_depth'])
            if row['family'] in workloads:
                assert workloads[row['family']] == workload
            else:
                workloads[row['family']] = workload
            elapsed = original['timings_ms']['evaluator_total_ms']
            assert elapsed > 0
            times[backend].append(elapsed)
            del original
            # Decimal140 recomputation uses raw messages and encrypted factors;
            # neither cached oracle flags nor C++ reference values are trusted.
            recomputed = verify(folder/'output.json')
            assert recomputed == row['oracle'] and recomputed['accepted']
            cases.append({'backend': backend, 'case': row['case'],
                          'output_sha256': row['files_sha256']['output.json'],
                          'result_sha256': digest(folder/'result.json'),
                          'recomputed_oracle': recomputed,
                          'evaluator_total_ms_from_output': elapsed})
            print(name, backend, row['case'], 'independently verified', flush=True)
    medians = {b: median(values) for b, values in times.items()}
    ratio = medians['p03']/medians['native']
    assert medians['native'] == stored['native_median_ms']
    assert medians['p03'] == stored['p03_median_ms']
    assert ratio == stored['time_ratio']
    result = {'stage': 'independent_full_slot_publication_audit', 'all_passed': True,
              'run_id': run_id, 'source_commit': expected_commit,
              'source_identity': expected_identity, 'runner_sha256': expected_scripts,
              'frozen_merge_checker_sha256': stored['checker_sha256'],
              'audit_script_sha256': digest(Path(__file__)),
              'k': k, 'slots': slots, 'trial': trial, 'cases': cases,
              'checked_slots': sum(c['recomputed_oracle']['checked_slots'] for c in cases),
              'medians_from_native_output_ms': medians, 'within_runner_ratio': ratio,
              'github_run_url': state['url'], 'github_job': job, 'github_artifact': attachment,
              'github_archive_sha256': archive_sha, 'archive_members_sha256': archive_members,
              'source_note': 'Job-to-artifact mapping follows the pinned workflow matrix and upload names; metadata is preserved, not a hardware attestation.'}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2)+'\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('artifact', type=Path)
    p.add_argument('output', type=Path)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--run-metadata', type=Path, required=True)
    p.add_argument('--artifacts-metadata', type=Path, required=True)
    p.add_argument('--source-commit', required=True)
    a = p.parse_args()
    audit(a.artifact, a.output, a.archive, a.run_metadata, a.artifacts_metadata, a.source_commit)


if __name__ == '__main__':
    main()
