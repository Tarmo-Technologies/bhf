# SPDX-License-Identifier: Apache-2.0
"""Architecture-specific tool downloads and Rust inventory must agree."""
import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('toolchain_inventory', ROOT / 'scripts/ci/toolchain-image-inventory.py')
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)


class ToolchainPlatformTests(unittest.TestCase):
    def values(self, architecture):
        result = subprocess.run(['sh', '-c', '. "$1"; bhf_toolchain_platform "$2" || exit; '
                                 'printf "%s\\n" "$BHF_RUST_HOST" "$BHF_NODE_ARCH" "$BHF_GO_ARCH" '
                                 '"$BHF_RUSTUP_SHA256" "$BHF_NODE_SHA256" "$BHF_GO_SHA256"',
                                 'sh', str(ROOT / 'docker/toolchain-platform.sh'), architecture],
                                capture_output=True, text=True)
        return result

    def test_tool_architectures_and_independent_checksums(self):
        sums = []
        for arch, rust_host, node in [('amd64', 'x86_64-unknown-linux-gnu', 'x64'),
                                      ('arm64', 'aarch64-unknown-linux-gnu', 'arm64')]:
            result = self.values(arch)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.splitlines()
            self.assertEqual(lines[:3], [rust_host, node, arch])
            self.assertEqual(len(lines), 6)
            for digest in lines[3:]:
                self.assertRegex(digest, r'^[0-9a-f]{64}$')
            sums.extend(lines[3:])
        self.assertEqual(len(set(sums)), 6)

    def test_unsupported_architectures_fail(self):
        for arch in ('386', 'riscv64', '', 'amd64,arm64'):
            result = self.values(arch)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')

    def test_installed_rust_components_use_observed_host(self):
        for host in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'):
            details = f'rustc 1.99.0\nhost: {host}\nrelease: 1.99.0\n'
            for name in ('rustc', 'rust-std', 'llvm-tools-preview'):
                self.assertEqual(INVENTORY.rust_component_name(name + '-' + host, details), name)
            self.assertEqual(INVENTORY.rust_component_name('rust-docs', details), 'rust-docs')


if __name__ == '__main__':
    unittest.main()
