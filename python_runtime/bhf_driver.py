# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""bhf Python fork-server driver — the Python analog of c_runtime/bhf_driver.c
and java_runtime Driver.java. Speaks the SAME BHF_FRAMED protocol so the
builtin engine drives a warm, long-lived interpreter one input at a time
(amortizing interpreter + import startup), exactly like a C/Rust fork-server
binary — no Atheris, no libFuzzer.

Protocol (must match the C driver):
  1. Save the engine's control pipe (fd 1) to a private fd, then redirect fd 1 to
     /dev/null so the target's stdout can't corrupt the sync stream (#427).
  2. Write one ready byte to the control fd.
  3. Loop: read {u32 little-endian length, bytes} from fd 0, run the harness,
     write one sync byte to the control fd.
An uncaught FINDING exception halts the process (exit 86) with no sync byte, so
the engine sees the death and re-isolates the input. An expected rejection
(input validation) is swallowed — the input is just rejected.

Without BHF_FRAMED, argv[1] is a single input file to replay once (the engine's
per-spawn crash-isolation path), else stdin is read.

Runs on Python 2.7 as well as Python 3 (#285): no annotations or f-strings,
and the exceptions Python 2 lacks or splits (StopAsyncIteration, IOError
beside OSError) are named through what it has.
"""
import importlib
import os
import struct
import sys
import traceback

import bhf_cov

FINDING_HALT_CODE = 86

# Exceptions that are input *rejection* or a HARNESS ARTIFACT, never a target bug.
# Python is dynamically typed and bhf synthesizes arguments, so a whole class
# of exceptions come from us calling with the wrong TYPE or SHAPE, not from a
# target defect — suppressing them is the key to avoiding a false-positive storm:
#   - ValueError: the canonical "bad value" (covers UnicodeDecodeError /
#     json.JSONDecodeError subclasses) — input validation.
#   - TypeError: usually our untyped decoder handing the wrong type.
#   - AttributeError: our wrong type lacking an attribute (e.g. `bytes` has no
#     `.timetuple()` when the target wanted a `str`). In a TYPED lane (Java) the
#     NPE analog is a real bug; in an untyped lane it is dominated by our-fault.
#   - KeyError: a synthesized container (`{}`) missing a key the target's internal
#     calling convention pre-seeds — our wrong shape. (Listed explicitly, NOT its
#     base LookupError, so IndexError — a real OOB on the bytes we feed — stays.)
#   - OSError: environmental. EOFError/StopIteration: normal stream end.
# Genuine bugs still surface: IndexError (real OOB on the real bytes we feed →
# BHF-201), RecursionError (BHF-207), MemoryError (BHF-209), ArithmeticError
# (BHF-205), AssertionError + SystemError + custom errors (BHF-210). Campaigns tune
# this boundary. This lane has no behavioral sink oracles yet (the runtrace shim
# is not loaded into the interpreter), so an injection that raises nothing is not
# reported.
try:
    _STOP_ASYNC = StopAsyncIteration
except NameError:  # Python 2
    _STOP_ASYNC = StopIteration
# EnvironmentError is OSError on Python 3 and the base of Python 2's separate
# IOError and OSError.
REJECTION_EXC = (
    ValueError, TypeError, AttributeError, KeyError, UnicodeError, EOFError,
    NotImplementedError, EnvironmentError, StopIteration, _STOP_ASYNC,
)
# Never a finding: interpreter control-flow signals (a target calling sys.exit or
# being interrupted is not a crash).
CONTROL_EXC = (KeyboardInterrupt, SystemExit, GeneratorExit)


def _expected_exceptions():
    raw = os.environ.get("BHF_EXPECTED_EXCEPTIONS", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


_EXPECTED = _expected_exceptions()
# Top-level package of the target module (set by the launcher). An exception whose
# type is DEFINED IN the target's own package is that library's declared way of
# rejecting input (e.g. configparser.MissingSectionHeaderError, email.errors.*) —
# intended error handling, not a bhf finding. This mirrors the Ada "declared
# exception = intended rejection" and Java `throws`-suppression principles. Builtin
# bug classes (RecursionError, IndexError; __module__ == "builtins") never match,
# so real faults still surface.
_TARGET_PKG = os.environ.get("BHF_TARGET_PACKAGE", "")


def _is_library_exception(exc):
    if not _TARGET_PKG:
        return False
    module = type(exc).__module__ or ""
    return module == _TARGET_PKG or module.split(".", 1)[0] == _TARGET_PKG


def _is_finding(exc):
    if isinstance(exc, CONTROL_EXC):
        return False
    if type(exc).__name__ in _EXPECTED:
        return False
    if isinstance(exc, REJECTION_EXC):
        return False
    if _is_library_exception(exc):
        return False
    return True


def _report_finding(exc):
    # Marker mirrors the JVM driver's `== bhf JVM finding:`; the engine's
    # `parse_python_finding` maps the exception type -> BHF rule -> CWE.
    # M22: `.format()` not an f-string, so this driver imports on Python 3.0-3.5
    # (legacy gov/mil interpreters) where f-strings are a SyntaxError at import.
    sys.stderr.write(
        "== bhf python finding: {0}: {1}\n".format(type(exc).__name__, exc)
    )
    traceback.print_exc()
    sys.stderr.flush()


def _load_run_one():
    mod_name = sys.argv[0] if len(sys.argv) > 0 and sys.argv[0] else os.environ.get("BHF_HARNESS_MODULE", "")
    # When invoked as `python bhf_driver.py <harness_module>`, argv[0] is the
    # driver path; the harness module name is argv[1] in non-framed... but we
    # standardize on BHF_HARNESS_MODULE to avoid colliding with the replay
    # file argv. The launcher sets it.
    mod_name = os.environ.get("BHF_HARNESS_MODULE", "bhfgen.harness")
    mod = importlib.import_module(mod_name)
    return getattr(mod, "bhf_run_one")


# The file the runtrace shim reads the current input from, when bhf preloads
# it (#300): the shim cannot see this process's bytes otherwise, so a sink the
# target reached could not be traced back to the input. One per process, since
# bhf runs fresh processes beside this one; removed at exit.
_SHIM_INPUT_FILE = (
    "{0}.{1}".format(os.environ["BHF_SHIM_INPUT_FILE"], os.getpid())
    if os.environ.get("BHF_SHIM_INPUT_FILE")
    else None
)


def _remove_published_input():
    try:
        os.unlink(_SHIM_INPUT_FILE)
    except OSError:
        pass


if _SHIM_INPUT_FILE is not None:
    import atexit

    atexit.register(_remove_published_input)


def _publish_input(data):
    if _SHIM_INPUT_FILE is None:
        return
    try:
        fd = os.open(_SHIM_INPUT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    except OSError:
        return
    try:
        while data:
            data = data[os.write(fd, data) :]
    except OSError:
        pass
    finally:
        os.close(fd)


def _run_input(run_one, data):
    bhf_cov.reset_prev()
    _publish_input(data)
    try:
        run_one(data)
    except BaseException as exc:  # noqa: BLE001 - we classify, then re-decide
        if _is_finding(exc):
            _report_finding(exc)
            os._exit(FINDING_HALT_CODE)
        # else: expected rejection — swallow, input just rejected.


def _arm_hang_report(run_one):
    """In bhf's re-run of an input that hung, print the frames the target is
    running once the run reaches BHF_HANG_REPORT_MS, then halt: bhf keys the
    hang finding on them. SIGALRM's handler runs between bytecodes, so a
    target looping in Python is interrupted where it loops."""
    after = os.environ.get("BHF_HANG_REPORT_MS")
    if not after:
        return
    try:
        seconds = int(after) / 1000.0
    except ValueError:
        return
    import signal

    if not hasattr(signal, "setitimer"):
        return
    own = set()
    harness = getattr(getattr(run_one, "__code__", None), "co_filename", __file__)
    for path in (__file__, bhf_cov.__file__, harness):
        own.add(os.path.realpath(path))
    prefix = os.environ.get("BHF_TRACE_PREFIX") or None

    def is_target(path):
        real = os.path.realpath(path)
        if real in own:
            return False
        return prefix is None or real.startswith(os.path.realpath(prefix))

    def report(_signum, frame):
        sys.stderr.write("== bhf hang: python\n")
        shown = 0
        while frame is not None and shown < 5:
            code = frame.f_code
            if is_target(code.co_filename):
                sys.stderr.write(
                    "== bhf frame: {0} @ {1}:{2}\n".format(
                        code.co_name, code.co_filename, frame.f_lineno
                    )
                )
                shown += 1
            frame = frame.f_back
        sys.stderr.flush()
        os._exit(FINDING_HALT_CODE)

    signal.signal(signal.SIGALRM, report)
    signal.setitimer(signal.ITIMER_REAL, seconds)


def _read_u32(fd):
    buf = b""
    while len(buf) < 4:
        chunk = os.read(fd, 4 - len(buf))
        if not chunk:
            return -1
        buf += chunk
    return struct.unpack("<I", buf)[0]


def _read_exact(fd, n):
    buf = b""
    while len(buf) < n:
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _framed_loop(run_one):
    # Save control pipe (fd 1) then redirect stdout to /dev/null so target prints
    # can't corrupt the sync stream (#427).
    control_fd = os.dup(1)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    os.write(control_fd, b"\x01")  # ready byte
    _count = 0
    while True:
        n = _read_u32(0)
        if n < 0:
            break
        data = _read_exact(0, n)
        _run_input(run_one, data)
        os.write(control_fd, b"\x01")  # sync byte
        # Periodically persist covered lines for negative fuzz-confirmation; the
        # dump no-ops unless the covered set grew (coverage plateaus, so writes are
        # rare after warmup) and unless BHF_COVERED_LINES is set.
        _count += 1
        # Persist at exponentially spaced early checkpoints, then every 512
        # inputs. Short campaigns used to die before the first 512-input dump
        # and therefore lost all line evidence despite entering the target.
        if (_count & (_count - 1)) == 0 or (_count & 0x1FF) == 0:
            bhf_cov.dump_covered_lines()


def main():
    traced_prefix = os.environ.get("BHF_TRACE_PREFIX") or None
    bhf_cov.install(traced_prefix)
    run_one = _load_run_one()
    _arm_hang_report(run_one)
    if os.environ.get("BHF_FRAMED") is not None:
        _framed_loop(run_one)
        bhf_cov.dump_covered_lines()
        return
    # Per-spawn single-input replay.
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        with open(sys.argv[1], "rb") as f:
            data = f.read()
    else:
        data = getattr(sys.stdin, "buffer", sys.stdin).read()
    _run_input(run_one, data)
    bhf_cov.dump_covered_lines()


if __name__ == "__main__":
    main()
