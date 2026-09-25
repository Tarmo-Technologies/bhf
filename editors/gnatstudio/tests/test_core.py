# SPDX-License-Identifier: Apache-2.0

import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bhf_gnatstudio_core import (
    BhfConfig,
    StdioJsonRpcClient,
    action_name,
    build_minimize_args,
    build_replay_args,
    diagnostic_records,
    encode_frame,
    finding_action_specs,
    read_frame,
    resolve_reproducer_path,
)


FINDING = {
    "id": "F-0001-alpha",
    "severity": "high",
    "classification": "swallowed_predefined",
    "signature": "aabbccdd",
    "exception": {
        "handler": {
            "file": "src/pkg.adb",
            "line": 5,
            "col": 7,
        },
        "last_breadcrumb": {
            "file": "src/pkg.adb",
            "line": 3,
            "col": 2,
        },
    },
    "generated_repro_ada": "F-0001-alpha/repro.adb",
    "replay": {
        "command": "bhf replay --finding F-0001-alpha",
    },
}


class CoreTests(unittest.TestCase):
    def test_frame_round_trip(self):
        frame = encode_frame({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})

        self.assertTrue(frame.startswith(b"Content-Length: "))
        self.assertEqual(
            read_frame(io.BytesIO(frame)),
            {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
        )

    def test_read_frame_rejects_oversized_header_and_body(self):
        with self.assertRaisesRegex(ValueError, "header exceeds"):
            read_frame(io.BytesIO(b"X: " + b"a" * 8192))
        with self.assertRaisesRegex(ValueError, "body exceeds"):
            read_frame(io.BytesIO(b"Content-Length: 67108865\r\n\r\n"))

    def test_daemon_client_reads_response_and_reaps_child(self):
        program = (
            "import sys; "
            "body=b'{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"findings\":[]}}'; "
            "sys.stdout.buffer.write(b'Content-Length: '+str(len(body)).encode()+b'\\r\\n\\r\\n'+body); "
            "sys.stdout.buffer.flush()"
        )
        client = StdioJsonRpcClient(sys.executable, timeout_secs=1, args=["-c", program])
        try:
            self.assertEqual(client.request("findings"), {"findings": []})
        finally:
            client.close()
        self.assertIsNotNone(client.process.poll())
        self.assertFalse(client._reader.is_alive())

    def test_daemon_client_times_out_on_silent_or_partial_response(self):
        programs = (
            "import time; time.sleep(30)",
            "import sys,time; sys.stdout.buffer.write(b'Content-Length: 100\\r\\n\\r\\n{}'); sys.stdout.buffer.flush(); time.sleep(30)",
        )
        for program in programs:
            with self.subTest(program=program):
                client = StdioJsonRpcClient(sys.executable, timeout_secs=0.1, args=["-c", program])
                started = time.monotonic()
                with self.assertRaisesRegex(TimeoutError, "exceeded"):
                    client.request("findings")
                self.assertLess(time.monotonic() - started, 2.5)
                self.assertIsNotNone(client.process.poll())
                self.assertFalse(client._reader.is_alive())

    def test_daemon_client_reaps_child_that_exits_before_response(self):
        client = StdioJsonRpcClient(sys.executable, timeout_secs=1, args=["-c", "import sys; sys.exit(3)"])
        with self.assertRaises((EOFError, BrokenPipeError)):
            client.request("findings")
        self.assertIsNotNone(client.process.poll())
        self.assertFalse(client._reader.is_alive())

    @unittest.skipUnless(os.name == "posix", "process group test requires POSIX")
    def test_daemon_client_timeout_stops_owned_grandchild(self):
        with tempfile.TemporaryDirectory() as temp:
            pid_file = Path(temp) / "grandchild.pid"
            program = (
                "import subprocess,sys,time; "
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                "open(sys.argv[1],'w').write(str(child.pid)); time.sleep(30)"
            )
            client = StdioJsonRpcClient(
                sys.executable,
                timeout_secs=0.2,
                args=["-c", program, str(pid_file)],
            )
            with self.assertRaises(TimeoutError):
                client.request("findings")
            self.assertIsNotNone(client.process.poll())
            self.assertFalse(client._reader.is_alive())
            if pid_file.exists():
                grandchild_pid = int(pid_file.read_text())
                status = Path(f"/proc/{grandchild_pid}/stat")
                if status.exists():
                    self.assertEqual(status.read_text().split()[2], "Z")

    def test_diagnostic_records_map_finding_to_gnatstudio_message(self):
        records = diagnostic_records([FINDING], "/work/project")

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].finding_id, "F-0001-alpha")
        self.assertEqual(records[0].file, os.path.normpath("/work/project/src/pkg.adb"))
        self.assertEqual(records[0].line, 5)
        self.assertEqual(records[0].column, 7)
        self.assertEqual(records[0].importance, "HIGH")
        self.assertIn("swallowed_predefined", records[0].text)
        self.assertIn("aabbccdd", records[0].text)

    def test_diagnostic_records_prefer_actionability_fix_location(self):
        finding = {
            **FINDING,
            "actionability": {
                "verdict": "real_reachable",
                "confidence": "high",
                "fix_location": {
                    "path": "src/fix.adb",
                    "line": 42,
                    "col": 4,
                    "reason": "explicit_raise_site",
                },
            },
        }

        records = diagnostic_records([finding], "/work/project")

        self.assertEqual(records[0].file, os.path.normpath("/work/project/src/fix.adb"))
        self.assertEqual(records[0].line, 42)
        self.assertEqual(records[0].column, 4)
        self.assertIn("real_reachable", records[0].text)
        self.assertIn("high", records[0].text)

    def test_diagnostic_records_fall_back_to_last_breadcrumb(self):
        finding = {
            **FINDING,
            "exception": {
                "last_breadcrumb": {
                    "file": "src/pkg.adb",
                    "line": 3,
                    "col": 2,
                },
            },
        }

        records = diagnostic_records([finding], "/work/project")

        self.assertEqual(records[0].line, 3)
        self.assertEqual(records[0].column, 2)

    def test_build_replay_args_use_harness_override_when_configured(self):
        config = BhfConfig(
            cli_path="bhf",
            daemon_path="bhf-daemon",
            findings_dir="findings",
            harness_path="build/H 1/main",
            minimize_strategy="typed",
            workspace_root="/work/project",
        )

        self.assertEqual(
            build_replay_args(FINDING, config),
            [
                "bhf",
                "replay",
                "--finding",
                os.path.normpath("/work/project/findings/F-0001-alpha"),
                "--harness",
                "build/H 1/main",
            ],
        )

    def test_build_replay_args_use_configured_findings_dir_with_harness_override(self):
        config = BhfConfig(
            cli_path="bhf",
            daemon_path="bhf-daemon",
            findings_dir="custom/findings",
            harness_path="build/H 1/main",
            minimize_strategy="typed",
            workspace_root="/work/project",
        )

        self.assertEqual(
            build_replay_args(FINDING, config),
            [
                "bhf",
                "replay",
                "--finding",
                os.path.normpath("/work/project/custom/findings/F-0001-alpha"),
                "--harness",
                "build/H 1/main",
            ],
        )

    def test_build_replay_args_ignore_finding_command_without_harness_override(self):
        config = BhfConfig(workspace_root="/work/project")

        self.assertEqual(
            build_replay_args({**FINDING, "replay": {"command": "evil-command"}}, config),
            ["bhf", "replay", "--finding", "/work/project/findings/F-0001-alpha"],
        )

    def test_build_replay_args_reject_path_escape_id(self):
        config = BhfConfig(workspace_root="/work/project")
        with self.assertRaisesRegex(ValueError, "invalid ID"):
            build_replay_args({**FINDING, "id": "../../outside"}, config)

    def test_build_minimize_args_include_strategy_and_harness(self):
        config = BhfConfig(
            harness_path="build/main",
            minimize_strategy="typed",
            workspace_root="/work/project",
        )

        self.assertEqual(
            build_minimize_args(FINDING, config),
            [
                "bhf",
                "minimize",
                "--finding",
                os.path.normpath("/work/project/findings/F-0001-alpha"),
                "--harness",
                "build/main",
                "--strategy",
                "typed",
            ],
        )

    def test_build_minimize_args_use_configured_findings_dir(self):
        config = BhfConfig(
            findings_dir="/tmp/bhf-findings",
            harness_path="",
            minimize_strategy="typed",
            workspace_root="/work/project",
        )

        self.assertEqual(
            build_minimize_args(FINDING, config),
            [
                "bhf",
                "minimize",
                "--finding",
                os.path.normpath("/tmp/bhf-findings/F-0001-alpha"),
                "--strategy",
                "typed",
            ],
        )

    def test_resolve_reproducer_path_uses_findings_root(self):
        config = BhfConfig(
            findings_dir="findings",
            workspace_root="/work/project",
        )

        self.assertEqual(
            resolve_reproducer_path(FINDING, config),
            os.path.normpath("/work/project/findings/F-0001-alpha/repro.adb"),
        )

    def test_action_name_is_deterministic_and_safe(self):
        self.assertEqual(
            action_name("replay", "F/0001 alpha"),
            "BHF replay F_0001_alpha",
        )

    def test_finding_action_specs_match_available_workflows(self):
        self.assertEqual(
            [spec.action for spec in finding_action_specs(FINDING)],
            ["replay", "minimize", "open-repro"],
        )

        finding_without_repro = {
            key: value for key, value in FINDING.items() if key != "generated_repro_ada"
        }
        self.assertEqual(
            [spec.action for spec in finding_action_specs(finding_without_repro)],
            ["replay", "minimize"],
        )


if __name__ == "__main__":
    unittest.main()
