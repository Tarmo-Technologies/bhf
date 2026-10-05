#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit, local image construction/runtime smoke matrix (not a scored sweep).

Reuse the release builder and benign language/runtime controls. Every image is
built from the same clean commit. No third-party target code is downloaded/run.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
LANGUAGES = 'c,cpp,rust,java,python,perl,go,ada,cobol,fortran,csharp,javascript,typescript,ruby,lua,php'.split(',')


def run(args, logfile, timeout=1800):
    with logfile.open('w') as log:
        try:
            result = subprocess.run(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
            return result.returncode
        except subprocess.TimeoutExpired:
            log.write('\nORCHESTRATOR_TIMEOUT\n')
            return 124


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=pathlib.Path)
    parser.add_argument('--selection', action='append', help='Override default full + 16 singles + 3 mixed matrix')
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    if any(evidence.iterdir()):
        parser.error('evidence directory must be empty; preserve previous attempts')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip():
        parser.error('requires a clean checkout')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    selections = args.selection or ['all', *LANGUAGES, 'java,python', 'c,cpp,ada', 'javascript,typescript']
    report = {'kind': 'image-construction-and-benign-runtime-smoke', 'source_commit': commit,
              'qualification_sweep': False, 'results': [], 'remaining': selections.copy()}
    def persist():
        temp = evidence / 'matrix.json.tmp'
        temp.write_text(json.dumps(report, indent=2) + '\n')
        temp.replace(evidence / 'matrix.json')
    persist()
    for index, selection in enumerate(selections):
        stage = evidence / str(index)
        stage.mkdir()
        image = f'bhf:selection-{commit[:12]}-{index}'
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
            command = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
                       '--tmpfs', '/tmp:rw,exec,nosuid,size=1g', '--memory', '4g', '--cpus', '2',
                       '--pids-limit', '512', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                       '--volume', f'{ROOT}/docker/language-smoke.sh:/language-smoke.sh:ro',
                       identity['Id'], 'bash', '/language-smoke.sh', selection]
            row['smoke_command'] = command
            row['toolchain_smoke_exit'] = run(command, stage / 'toolchain-smoke.log', 300)
            row['runtime_acceptance_exit'] = run(['bash', 'scripts/ci/container-runtime-acceptance.sh',
                                                  identity['Id'], str(stage)], stage / 'runtime.log', 60)
            row['status'] = 'passed' if row['toolchain_smoke_exit'] == row['runtime_acceptance_exit'] == 0 else 'runtime failure'
        else:
            row['status'] = 'build failure'
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)
        row['evidence'] = {str(p.relative_to(evidence)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in stage.iterdir() if p.is_file()}
        report['results'].append(row)
        report['remaining'] = selections[index + 1:]
        persist()
        print(json.dumps(row), flush=True)
    return 0 if all(x['status'] == 'passed' for x in report['results']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
