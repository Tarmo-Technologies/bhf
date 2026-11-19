# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""bhf Python coverage agent — the Python analog of java_runtime Coverage.java.

Joins bhf's file-backed edge map (path in BHF_COV_SHM, mmap MAP_SHARED,
BHF_COV_BITS = 1<<16) and records AFL-style edge hits into it from the
interpreter, using sys.monitoring (PEP 669, 3.12+) where available, else
sys.settrace. Pure stdlib — no coverage.py, no Atheris, no native helper.

Edge hash MUST match the C driver / Coverage.java:
    idx = (prev ^ block) & MASK ; map[idx]++ (saturating 0xff) ; prev = block >> 1
prev is reset to 0 at the start of each input so identical inputs hash to
identical edges (deterministic coverage).

Runs on Python 2.7 as well as Python 3 (#285), where a map byte is a
one-character `str` and settrace is the only backend.
"""
import mmap
import os
import sys

_PY2 = sys.version_info[0] < 3
# os.replace is Python 3.3+; on POSIX os.rename replaces the same way.
_replace = getattr(os, "replace", os.rename)

COV_BITS = 1 << 16
COV_MASK = COV_BITS - 1

_map = None
_prev = 0
_traced_prefix = None
_tool_id = 1

# Covered (file:line) set for negative fuzz-confirmation: a static finding whose
# line the fuzzer EXECUTED without a crash/finding is exercised-and-survived (weak
# evidence of a false positive), distinct from a line never reached. Captured only
# when BHF_COVERED_LINES names a sidecar; dumped periodically by the driver.
_covered = set()
_covered_dumped = 0


def note_line(filename, lineno):
    _covered.add("{0}:{1}".format(filename, lineno))


def dump_covered_lines():
    """Write the covered (file:line) set to BHF_COVERED_LINES when it grew.
    Cheap + best-effort: skipped if unset, no-op if nothing new since last dump."""
    global _covered_dumped
    path = os.environ.get("BHF_COVERED_LINES")
    if not path or len(_covered) == _covered_dumped:
        return
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            fh.write("\n".join(sorted(_covered)))
        _replace(tmp, path)
        _covered_dumped = len(_covered)
    except Exception:
        pass


def _open():
    global _map
    path = os.environ.get("BHF_COV_SHM")
    if not path:
        return None
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        if os.fstat(fd).st_size < COV_BITS:
            os.ftruncate(fd, COV_BITS)
        if hasattr(mmap, "MAP_SHARED"):
            m = mmap.mmap(fd, COV_BITS, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        else:
            # Windows: a file mapping is shared with every process mapping the
            # same file, which is how the engine reads it.
            m = mmap.mmap(fd, COV_BITS, access=mmap.ACCESS_WRITE)
        os.close(fd)
        return m
    except Exception:
        return None


def enabled():
    return _map is not None


def reset_prev():
    global _prev
    _prev = 0


def _record(block):
    global _prev
    m = _map
    if m is None:
        return
    idx = (_prev ^ block) & COV_MASK
    v = m[idx]
    if v != 0xFF:
        m[idx] = v + 1
    _prev = (block >> 1) & COV_MASK


if _PY2:

    def _record(block):  # noqa: F811 - a Python 2 map byte is a 1-char str
        global _prev
        m = _map
        if m is None:
            return
        idx = (_prev ^ block) & COV_MASK
        v = ord(m[idx])
        if v != 0xFF:
            m[idx] = chr(v + 1)
        _prev = (block >> 1) & COV_MASK


# The FNV-1a state after each file name's bytes, so a name is hashed once
# rather than on every line event.
_file_hash = {}


def _name_hash(filename):
    h = _file_hash.get(filename)
    if h is None:
        name = filename if isinstance(filename, bytes) else filename.encode("utf-8", "replace")
        h = 0xCBF29CE484222325
        for byte in bytearray(name):
            h = ((h ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        _file_hash[filename] = h
    return h


def _block_id(filename, lineno):
    # Stable per (file,line). hash() is salted per-process for str, so use a
    # deterministic FNV-1a over the bytes instead — coverage must be reproducible.
    h = _name_hash(filename)
    h = ((h ^ (lineno & 0xFF)) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    h = ((h ^ ((lineno >> 8) & 0xFF)) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h & COV_MASK


# ---- sys.monitoring backend (3.12+) ----

def _install_monitoring(prefix):
    mon = sys.monitoring
    mon.use_tool_id(_tool_id, "bhf")
    E = mon.events

    def on_line(code, line_number):
        fn = code.co_filename
        if prefix is None or fn.startswith(prefix):
            _record(_block_id(fn, line_number))
            note_line(fn, line_number)
        return mon.DISABLE if False else None

    mon.register_callback(_tool_id, E.LINE, on_line)
    mon.set_events(_tool_id, E.LINE)


# ---- settrace backend (fallback) ----

def _install_settrace(prefix):
    def tracer(frame, event, arg):
        if event == "line":
            fn = frame.f_code.co_filename
            if prefix is None or fn.startswith(prefix):
                _record(_block_id(fn, frame.f_lineno))
                note_line(fn, frame.f_lineno)
        return tracer
    sys.settrace(tracer)
    # settrace only applies to frames entered after the call; threads need
    # settrace too, but the harness is single-threaded per input.


def install(traced_prefix=None):
    """Arm coverage. traced_prefix limits instrumentation to files under that path
    (the target/harness source root) so stdlib/driver noise is excluded."""
    global _map, _traced_prefix
    _map = _open()
    _traced_prefix = traced_prefix
    if _map is None:
        return False
    if hasattr(sys, "monitoring"):
        try:
            _install_monitoring(traced_prefix)
            return True
        except Exception:
            pass
    _install_settrace(traced_prefix)
    return True
