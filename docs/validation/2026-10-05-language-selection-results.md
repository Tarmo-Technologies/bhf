<!-- SPDX-License-Identifier: Apache-2.0 -->
# Language-selection matrix results

This is compact evidence for the local construction and functional matrix at
commit `12d6066662daa68cbe242919d311f663d90ea0bf`. The source-archive SHA-256 is
`2f6ff150ec95613cc31527dbbf3427c6d55f4e4fe8f969ce6fda37394479e2a0`.
All images were built from that clean checkout without inheriting an
all-language image. Each row passed its selected-toolchain receipt, excluded
ecosystem checks, non-root disconnected/read-only runtime checks, daemon
termination, malformed-option behavior, dummy-provider/no-LLM controls, and
BHF-owned clean `bhf auto` controls.

| Selection | Local image configuration ID | Unpacked bytes | Result |
|---|---|---:|---|
| all | `a3565b7e4c3c` | 3,647,380,700 | PASS |
| C | `d729a9f8fb68` | 1,243,083,638 | PASS |
| C++ | `ab8034a9d89e` | 1,243,083,640 | PASS |
| Rust | `6b24fe9c2132` | 2,096,099,063 | PASS |
| Java | `7beffb6f029c` | 1,370,988,385 | PASS |
| Python | `d817c2198338` | 1,124,787,118 | PASS |
| Perl | `94d6af523820` | 1,053,558,558 | PASS |
| Go | `2913258c7d58` | 1,487,010,764 | PASS |
| Ada | `276fa92f756d` | 1,400,145,341 | PASS |
| COBOL | `5182723cfbc8` | 1,250,287,423 | PASS |
| Fortran | `379e577fb187` | 1,285,096,194 | PASS |
| C# | `f34c3b385355` | 1,574,291,228 | PASS |
| JavaScript | `d3917a375c7c` | 1,180,311,672 | PASS |
| TypeScript | `2e309c12fb61` | 1,191,740,693 | PASS |
| Ruby | `7c54582cf34a` | 1,088,903,762 | PASS |
| Lua | `b94c803d5ca4` | 1,059,165,525 | PASS |
| PHP | `bd344027aa39` | 1,071,027,734 | PASS |
| Java, Python | `dde65f772eec` | 1,442,216,871 | PASS |
| C, C++, Ada | `8d2512f07e01` | 1,400,145,347 | PASS |
| JavaScript, TypeScript | `0ff34de9c10e` | 1,191,740,704 | PASS |

The full image's automatic controls produced these clean results. Every target
entry flag was true; each row had 32 executions and zero findings.

| Language | Entered target | Measured edges |
|---|---|---:|
| Ada | `checksum` | 107 |
| C | `packet_checksum` | 6 |
| C++ | `packet_checksum` | 18 |
| Rust | `packet_checksum` | 27 |
| Java | `packetChecksum` | 17 |
| Python | `packet_checksum` | 2 |
| Perl | `Packet::packet_checksum` | 7 |
| Go | `PacketChecksum` | 14 |
| COBOL | `PACKETCHECKSUM` | 37 |
| Fortran | `PACKET_CHECKSUM` | 151 |
| C# | `Packet.PacketChecksum` | 5 |
| JavaScript | `packet_checksum` | 3 |
| TypeScript | `packet_checksum` | 10 |
| Ruby | `Packet.packet_checksum` | 1 |
| Lua | `M.packet_checksum` | 4 |
| PHP | `packet_checksum` | 4 |

The complete matrix JSON hashes to
`aa83811a4e6bb652b4a9b703aada7ede8ac3a96f98f3b0b74258efcc6d1e9711`.
The full-image automatic-control JSON hashes to
`f916723ad99fe00c7e6c000197f29f29f1e49d0f9bd2db89d6c182b441f4256a`.
Raw logs remain local under `/tmp/bhf-qualification-20261005`; this committed
summary does not claim those workspace paths are contractor-download links.

The exact all-language image inventory used Syft 1.46.0, Grype 0.115.0, and a
valid Grype database built 2026-10-04T08:11:47Z. The enforced gate reported zero
blockers and 829 residual matches: 678 Medium, 141 Low, and 10 Negligible. These
matches remain untriaged and require protected human review. The CycloneDX JSON
hashes to `1ed6d80f0ba2de4d9729bc9251f4025a8bce3473161b2e90e0afc60bcf665926`;
the Grype JSON hashes to
`e27bd156a317f7432fe4c623bb0b3b8d92377fc27247ce17b6ace15beb496794`.

This matrix proves selected distribution construction and short owned-control
functionality. It is not the scored 100-project qualification campaign, a
vulnerability-free assertion, publisher authentication, or release approval.
