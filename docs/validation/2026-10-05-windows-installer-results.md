<!-- SPDX-License-Identifier: Apache-2.0 -->
# Retained Windows installer validation

The retained Proxmox Windows guests passed installation of the actual
cargo-dist CLI and daemon archives, followed by the shared native C smoke.
These checks used Windows PowerShell 5.1 over OpenSSH with existing trusted
host keys. They exercise a BHF-owned fixture and establish installation and
native execution; they do not score third-party vulnerability discovery.

## Tested artifacts

The archives and corrected PowerShell installers came from CI run
`37310378641`, artifact `11345898269` (`bhf-windows-components`). The downloaded
artifact hashes to
`fbd19ebcecb16bf11eb3dbe7cae869f6c86017c6b614f8c795a89319dd052fe0`.
The compiled source is PR merge commit
`0b9a564a263c447c4d5c54d305fd803affa43b5b`, whose tracked tree matches branch
head `d9a4428d91d07d32f28edb879f846d5e7ed5e5cb`. Later installer CI fixes and
documentation changes are not represented by that artifact identity.

Each installer used a local `file:` download URL, a new install prefix with
spaces in its path, and disabled PATH modification. The validation compared
each archive with its cargo-dist SHA-256 sidecar and each installed executable
with the executable inside its archive. Both installed programs reported the
tested source commit; the CLI reported `bhf v0.2.35`.

The shared smoke accepted the explicit source commit because these guests do
not have Git. It checked version identity, daemon help, scan, target discovery,
LLVM/Visual Studio compilation, and public `bhf auto` execution of the owned
`magic_byte` fixture's `parse_frame` target.

## Results

| Guest | VM | OS build | Installed components | Native result |
|---|---|---|---|---|
| Windows Server 2019 Standard Evaluation | 114 | 17763 | CLI and daemon PASS | One non-stub target, 32 executions, nine measured edges, zero findings |
| Windows 11 Enterprise 25H2 Evaluation | 115 | 26200 | CLI and daemon PASS | One non-stub target, 32 executions, nine measured edges, zero findings |
| Windows 11 Enterprise LTSC 2024 Evaluation | 116 | 26100 | CLI and daemon PASS | One non-stub target, 32 executions, nine measured edges, zero findings |

The deliberately faulty fixture emitted no findings in these sanitizer-disabled
runs. Those results did not validate default sanitizers or detection of its
intended fault. Hosted CI separately exercises installers under PowerShell Core.

## Default packaged customer command

Final CI run `37321367468` passed every required job. Its Windows component
artifact `11350274760` hashes to
`6d62aa183b4a0f7536991b2b792935b345c2ded72bd9440e02d4a3bb33841d10`.
The compiled source is `d1bd11b74f690bbe70e8ccf61b0a223cbd65e63c`, whose
tracked tree equals branch commit `d3509e35766c56a377f6735bfd5a5b228492c5c4`.

The actual generated installers were repeated on all three guests. The shared
smoke now runs the README command with `--jobs 1 --max-targets 1
--per-target-time 10`, keeping default sanitizers and the default pass cascade.
It requires measured executions, coverage, and the documented reports.

| Guest | Executions | Measured edges | Findings |
|---|---|---|---|
| Server 2019 | 242 | 11 | One intended ASan stack-buffer-overflow |
| Windows 11 25H2 | 643 | 11 | One intended ASan stack-buffer-overflow |
| Windows 11 LTSC 2024 | 655 | 11 | One intended ASan stack-buffer-overflow |

A separate clean C++ default run on Server 2019 completed 30,507 executions,
measured 38 edges, and produced zero findings. The combined C-run summary
`windows-default-platform-summary-d1bd11b7.json` hashes to
`5f69be96d35df6c94641219ae11f36aa43b34a6f4b28193ac942e8057536f147`.
All guests were restored to their initial stopped states and original boot
orders after evidence capture. Horizon remained running.

## Version 0.3.0 candidate

CI run `37335570954` rebuilt the component installers at version 0.3.0 and
passed every required job. Artifact `11357402799` (`bhf-windows-components`)
hashes to
`0aa431492595c6309c0c8274196d1ff0cfdc5757cb9148d5373783b498e32ff0`.
The binaries report CI merge source
`06f750fa2aed2acc88bdd512e6ae9e885ec55ead`, whose tracked tree matches
branch source `0eaca1ce4c916c76f10ff3404f06015e205dbc8b`. Hosted Server 2022
installation passed under Windows PowerShell and PowerShell Core.

The actual 0.3.0 installers and default sanitized command then passed again on
the three retained guests:

| Guest | Executions | Measured edges | Findings |
|---|---:|---:|---|
| Server 2019 | 201 | 11 | One intended ASan stack-buffer-overflow |
| Windows 11 25H2 | 607 | 11 | One intended ASan stack-buffer-overflow |
| Windows 11 LTSC 2024 | 684 | 11 | One intended ASan stack-buffer-overflow |

The combined summary hashes to
`b3cb09975a7ff4e16df778602e217ec3e6603af494fca028097b8e6e9456e34c`.
Each guest was shut down before the next one started, and all original boot
orders were restored. Horizon remained running.

## Evidence and cleanup

Raw logs, component hashes, run JSON, and installer receipts are retained under
`/tmp/bhf-qualification-20261005/windows-native`. The combined summary
`windows-platform-summary-0b9a564a.json` hashes to
`284389c5cf9b4aede87685fdda86e7a462244ed1bdea2cb878dd0f5a85107dc8`.
The individual installer/native receipts hash to:

- Server 2019: `c091271663bc88f3755d92115366e4fbf669cf15f9be9762916a932c3f84b3bb`.
- Windows 11 25H2: `2626a73cd92c166fb4f84acb2006cfea1513ea420b57c8e376214e5fd68b0ef5`.
- Windows 11 LTSC 2024: `e2c8b68dfbe36b4bc43054d4ccf6fb2137e912a7ea9d686bae70712d4a5cf62a`.

The guests ran one at a time and were shut down after evidence capture. Their
original boot orders were restored. A graceful shutdown request for
`horizon-win-client` timed out; it remained running, and no forced stop was used.
