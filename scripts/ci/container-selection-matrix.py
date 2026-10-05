#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit, local image construction/runtime smoke matrix (not a scored sweep).

Reuse the release builder and benign language/runtime controls. Every image is
built from the same clean commit. No third-party target code is downloaded/run.
"""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
LANGUAGES = 'c,cpp,rust,java,python,perl,go,ada,cobol,fortran,csharp,javascript,typescript,ruby,lua,php'.split(',')


def persist(report, evidence):
    temp = evidence / 'matrix.json.tmp'
    with temp.open('w') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(evidence / 'matrix.json')


def validate_resume(report, evidence, commit, source_sha, selections=None):
    if report.get('schema_version') != 2:
        raise ValueError('checkpoint predates resumable matrices; retain it and start a new evidence directory')
    if report.get('source_commit') != commit or report.get('source_archive_sha256') != source_sha:
        raise ValueError('source identity differs from checkpoint')
    recorded = report['selections']
    if selections is not None and selections != recorded:
        raise ValueError('selection order differs from checkpoint')
    results = report['results']
    if ([row['requested'] for row in results] != recorded[:len(results)]
            or report['remaining'] != recorded[len(results):]):
        raise ValueError('checkpoint progress differs from selection order')
    for row in results:
        for name, expected in row['evidence'].items():
            path = (evidence / name).resolve()
            if not path.is_relative_to(evidence.resolve()) or not path.is_file():
                raise ValueError(f'missing or invalid evidence: {name}')
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f'evidence hash differs: {name}')
    return report


def run(args, logfile, timeout=1800, cleanup_container=None):
    with logfile.open('w') as log:
        try:
            result = subprocess.run(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
            return result.returncode
        except subprocess.TimeoutExpired:
            log.write('\nORCHESTRATOR_TIMEOUT\n')
            log.flush()
            if cleanup_container:
                subprocess.run(['docker', 'rm', '-f', cleanup_container],
                               stdout=log, stderr=subprocess.STDOUT, timeout=30)
            return 124


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=pathlib.Path)
    parser.add_argument('--selection', action='append', help='Override default full + 16 singles + 3 mixed matrix')
    parser.add_argument('--resume', action='store_true', help='Continue the same source and selections, verifying retained evidence hashes')
    parser.add_argument('--auto', action='store_true', default=None,
                        help='Also exercise BHF-owned clean target-entry/coverage controls through bhf auto')
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    # The lock prevents two resumptions from assigning the same pending row.
    lock = (evidence / '.matrix.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error('another matrix process owns this evidence directory')
    if not args.resume and any(p.name != '.matrix.lock' for p in evidence.iterdir()):
        parser.error('evidence directory must be empty; preserve previous attempts')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip():
        parser.error('requires a clean checkout')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    source_sha = hashlib.sha256(subprocess.check_output(['git', 'archive', '--format=tar', 'HEAD'], cwd=ROOT)).hexdigest()
    if args.resume:
        try:
            report = validate_resume(json.loads((evidence / 'matrix.json').read_text()),
                                     evidence, commit, source_sha, args.selection)
        except (ValueError, KeyError, OSError) as error:
            parser.error(str(error))
        selections = report['selections']
        if args.auto is not None and args.auto != report.get('auto_controls', False):
            parser.error('automatic-control setting differs from checkpoint')
    else:
        selections = args.selection or ['all', *LANGUAGES, 'java,python', 'c,cpp,ada', 'javascript,typescript']
        report = {'schema_version': 2, 'kind': 'image-construction-and-benign-runtime-smoke',
                  'source_commit': commit, 'source_archive_sha256': source_sha,
                  'qualification_sweep': False, 'results': [], 'selections': selections,
                  'remaining': selections.copy(), 'auto_controls': bool(args.auto)}
    persist(report, evidence)
    for index in range(len(report['results']), len(selections)):
        # The release builder reads HEAD; reject concurrent source changes so
        # subsequent rows cannot silently use a different source identity.
        if (subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() != commit
                or subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip()):
            parser.error('checkout changed during matrix; checkpoint retained')
        selection = selections[index]
        stage = evidence / str(index)
        attempt = 1
        while stage.exists():
            attempt += 1
            stage = evidence / f'{index}-attempt-{attempt}'
        stage.mkdir()
        selection_id = hashlib.sha256(selection.encode()).hexdigest()[:10]
        image = f'bhf:selection-{commit[:12]}-{selection_id}'
        row = {'requested': selection, 'image': image}
        started = time.monotonic()
        command = ['bash', 'scripts/build-container-release.sh', image, '--languages', selection]
        row['build_command'] = command
        row['build_exit'] = run(command, stage / 'build.log')
        row['build_seconds'] = round(time.monotonic() - started, 3)
        if row['build_exit'] == 0:
            identity = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image]))[0]
            row['local_image_id'] = identity['Id']
            row['unpacked_bytes'] = identity['Size']
            (stage / 'image-inspect.json').write_text(json.dumps([identity], indent=2) + '\n')
            container_name = f'bhf-selection-{commit[:12]}-{os.getpid()}-{index}'
            command = ['docker', 'run', '--rm', '--name', container_name, '--network', 'none', '--read-only',
                       '--tmpfs', '/tmp:rw,exec,nosuid,size=1g', '--memory', '4g', '--cpus', '2',
                       '--pids-limit', '512', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                       '--volume', f'{ROOT}/docker/language-smoke.sh:/language-smoke.sh:ro',
                       identity['Id'], 'bash', '/language-smoke.sh', selection]
            row['smoke_command'] = command
            row['toolchain_smoke_exit'] = run(command, stage / 'toolchain-smoke.log', 300, container_name)
            row['runtime_acceptance_exit'] = run(['bash', 'scripts/ci/container-runtime-acceptance.sh',
                                                  identity['Id'], str(stage)], stage / 'runtime.log', 60)
            row['status'] = 'passed' if row['toolchain_smoke_exit'] == row['runtime_acceptance_exit'] == 0 else 'runtime failure'
            if report.get('auto_controls'):
                auto_name = container_name + '-auto'
                command = ['docker', 'run', '--rm', '--name', auto_name, '--network', 'none', '--read-only',
                           '--tmpfs', '/tmp:rw,exec,nosuid,size=1g',
                           '--tmpfs', '/work:rw,exec,nosuid,uid=10001,gid=10001,size=2g',
                           '--memory', '4g', '--cpus', '2', '--pids-limit', '512', '--shm-size', '2g',
                           '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                           '--volume', f'{ROOT}/docker/fixtures/language-auto:/fixtures:ro',
                           '--volume', f'{ROOT}/docker/language-auto-smoke.sh:/auto-smoke.sh:ro',
                           identity['Id'], 'bash', '/auto-smoke.sh', selection]
                row['auto_command'] = command
                row['auto_exit'] = run(command, stage / 'auto-smoke.log', 2100, auto_name)
                for line in (stage / 'auto-smoke.log').read_text().splitlines():
                    if line.startswith('BHF_AUTO_REPORT='):
                        (stage / 'auto-results.json').write_text(json.dumps(json.loads(line.split('=', 1)[1]), indent=2) + '\n')
                if row['auto_exit'] != 0 or not (stage / 'auto-results.json').is_file():
                    row['status'] = 'automatic control failure'
        else:
            row['status'] = 'build failure'
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)
        row['evidence'] = {str(p.relative_to(evidence)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in stage.iterdir() if p.is_file()}
        report['results'].append(row)
        report['remaining'] = selections[index + 1:]
        persist(report, evidence)
        print(json.dumps(row), flush=True)
    return 0 if all(x['status'] == 'passed' for x in report['results']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
