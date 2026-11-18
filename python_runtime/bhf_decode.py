# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""bhf Python decode runtime — the Python analog of c_runtime/bhf_decode.h.

A cursor over the raw fuzz input that decodes typed values left-to-right, drained
deterministically and zero-filling on exhaustion (so a short input still produces
a valid, stable call). Mirrors the C decoder's primitives so the same byte layout
decodes consistently across lanes.

Runs on Python 2.7 as well as Python 3 (#285): no annotations, and a byte of
a Python 2 `str` is read through `ord`.
"""
import struct
import sys

_PY2 = sys.version_info[0] < 3


class Cursor(object):
    __slots__ = ("data", "pos")

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def remaining(self):
        return len(self.data) - self.pos if self.pos < len(self.data) else 0

    def u8(self):
        if self.remaining() == 0:
            return 0
        v = self.data[self.pos]
        self.pos += 1
        return ord(v) if _PY2 else v

    def _take(self, n):
        avail = min(n, self.remaining())
        b = self.data[self.pos:self.pos + avail]
        self.pos += avail
        if avail < n:
            b = b + b"\x00" * (n - avail)
        return b

    def i32(self):
        return struct.unpack("<i", self._take(4))[0]

    def u32(self):
        return struct.unpack("<I", self._take(4))[0]

    def i64(self):
        return struct.unpack("<q", self._take(8))[0]

    def f64(self):
        return struct.unpack("<d", self._take(8))[0]

    def boolean(self):
        return (self.u8() & 1) == 1

    def bounded_i32(self, lo, hi):
        if hi <= lo:
            return lo
        return lo + (self.u32() % (hi - lo + 1))

    def bounded_length(self, lo, hi):
        return self.bounded_i32(lo, hi)

    def take_bytes(self, n):
        return self._take(n)

    def rest(self):
        b = self.data[self.pos:]
        self.pos = len(self.data)
        return b

    def text(self, max_len=4096):
        """A length-prefixed-ish string: one length byte scaled into [0, min(max_len, remaining)]."""
        n = self.bounded_length(0, min(max_len, max(self.remaining(), 0)))
        return self._take(n).decode("utf-8", "replace")


def open_cursor(data):
    return Cursor(data)
