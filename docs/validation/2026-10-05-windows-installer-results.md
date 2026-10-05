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

The clean fixture produced no findings as expected. These runs used
`--sanitizers none`; sanitizer and concurrency fidelity remain unexercised by
this smoke. Hosted CI separately exercises installers under PowerShell Core.

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
