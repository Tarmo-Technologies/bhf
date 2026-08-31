# SPDX-License-Identifier: Apache-2.0
# Inline suppression: an un-suppressed sink is flagged; a `# nosec` / scoped
# `# bhf:ignore` marker at the site drops the finding.
import subprocess


def run(cmd, cmd2, cmd3, cmd4):
    subprocess.run(cmd, shell=True)                     # EXPECT BHF-404
    subprocess.run(cmd2, shell=True)  # nosec
    subprocess.run(cmd3, shell=True)  # bhf:ignore[CWE-78]
    # bhf:ignore
    subprocess.run(cmd4, shell=True)
