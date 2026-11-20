# SPDX-License-Identifier: Apache-2.0
"""A small record parser with an Atheris harness (fuzz/fuzz_records.py)."""


class RecordError(Exception):
    """The parser's documented rejection of a malformed record."""


# The checksum width of each record kind the format defines.
_CHECKSUM_WIDTH = {0: 0, 1: 2}


def parse_record(kind, payload):
    if not payload.startswith(b"REC"):
        raise RecordError("missing magic")
    if payload[3:4] == b"!":
        # The planted bug: a flagged record looks up its kind's checksum
        # width, but the table holds kinds 0 and 1 only, so a flagged record
        # of kind 2 or 3 raises KeyError.
        width = _CHECKSUM_WIDTH[kind]
        return payload[4 : 4 + width]
    return payload[4:]
