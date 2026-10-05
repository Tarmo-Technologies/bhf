# SPDX-License-Identifier: Apache-2.0
"""Execute the shared resolver, build option rejection and native dry-run plan."""
import itertools
import pathlib
import random
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
RESOLVER = ROOT / 'scripts/language-selection.sh'
ALL = 'c,cpp,rust,java,python,perl,go,ada,cobol,fortran,csharp,javascript,typescript,ruby,lua,php'.split(',')


def resolve(value):
    return subprocess.run(['bash', '-c', 'source "$1"; bhf_resolve_languages "$2"',
                           'resolve', str(RESOLVER), value], capture_output=True, text=True)


class LanguageSelectionTests(unittest.TestCase):
    def test_all_and_singletons(self):
        self.assertEqual(resolve('all').stdout.strip().split(','), ALL)
        for lang in ALL:
            self.assertEqual(resolve(lang).stdout.strip(), lang)

    def test_aliases(self):
        aliases = {'cpp': ['c++', 'cxx', 'cc'], 'rust': ['rs'], 'python': ['py'],
                   'perl': ['pl'], 'go': ['golang'], 'cobol': ['cob', 'cbl'],
                   'fortran': ['f90', 'f', 'for'], 'csharp': ['cs', 'c#', 'dotnet', 'net'],
                   'javascript': ['js', 'node', 'nodejs', 'mjs', 'cjs'], 'typescript': ['ts', 'tsx'],
                   'ruby': ['rb'], 'lua': ['luajit'], 'php': ['php8', 'phtml']}
        for canonical, names in aliases.items():
            for alias in names:
                self.assertEqual(resolve(alias.upper()).stdout.strip(), canonical)

    def test_order_and_duplicate_invariance(self):
        rng = random.Random(20261005)
        for _ in range(100):
            selected = rng.sample(ALL, rng.randint(1, 16))
            shuffled = selected + selected
            rng.shuffle(shuffled)
            self.assertEqual(resolve(','.join(shuffled)).stdout.strip().split(','),
                             [x for x in ALL if x in selected])

    def test_rejects_ambiguous_or_empty_lists(self):
        for value in ['', ' ', 'none', 'all,c', 'c,all', ',java', 'java,', 'c,,rust', 'brainfuck', '$(id)']:
            result = resolve(value)
            self.assertEqual(result.returncode, 2, value)
            self.assertEqual(result.stdout, '')

    def test_shared_dependency_closure(self):
        def packages(languages):
            result = subprocess.run(['bash', '-c', 'source "$1"; bhf_language_packages container "$2"',
                                     'packages', str(RESOLVER), languages], capture_output=True, text=True, check=True)
            return result.stdout.splitlines()
        for language in ['rust', 'go', 'c', 'cpp', 'ada', 'cobol', 'fortran']:
            self.assertIn('clang', packages(language))
        for language in ['java', 'python', 'csharp', 'javascript', 'typescript', 'perl', 'php', 'lua']:
            self.assertNotIn('clang', packages(language))
        self.assertEqual(packages('java,python'), packages('py,java,java'))
        self.assertEqual(packages('js,ts'), [])  # Node installed from pinned archive.

    def test_contradictory_build_options_rejected_before_docker(self):
        for options in [['--languages', 'java', '--flavor', 'runtime'],
                        ['--flavor', 'core', '--languages', 'c'],
                        ['--languages', ''], ['--languages', 'c', '--languages', 'rust'],
                        ['--engines', 'llm'], ['--flavor', 'ada', '--engines', 'builtin']]:
            result = subprocess.run(['bash', str(ROOT / 'scripts/build-container-release.sh'), *options],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('clean source checkout', result.stderr)

    def test_native_plan_uses_same_selection(self):
        with tempfile.TemporaryDirectory(prefix='bhf native selection ') as tmp:
            root = pathlib.Path(tmp)
            (root / 'tool').mkdir()
            (root / 'tool/bhf').touch()
            args = ['bash', str(ROOT / 'scripts/install-dist.sh'), '--non-interactive', '--dry-run',
                    '--no-content', '--no-smoke', '--no-symlink', '--extras', 'none',
                    '--package-manager', 'apt-get', '--prefix', str(root / 'install')]
            for language in ALL + ['py,java,java']:
                result = subprocess.run(args + ['--languages', language], cwd=root, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('  languages: ' + resolve(language).stdout.strip(), result.stdout)
                if language == 'py,java,java':
                    plan = next(x for x in result.stdout.splitlines() if 'apt-get install' in x)
                    for absent in ['gnat', 'gfortran', 'nodejs', 'golang', 'clang', 'ruby']:
                        self.assertNotIn(absent, plan)
            for invalid in ['', 'none', 'all,rust', 'c,']:
                result = subprocess.run(args + ['--languages', invalid], cwd=root, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('apt-get', result.stdout)


if __name__ == '__main__':
    unittest.main()
