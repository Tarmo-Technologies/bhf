# SPDX-License-Identifier: Apache-2.0
"""The project's Atheris harness for recordlib, as OSS-Fuzz runs it."""
import sys

import atheris

with atheris.instrument_imports():
    import recordlib


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    kind = fdp.ConsumeIntInRange(0, 3)
    payload = fdp.ConsumeBytes(atheris.ALL_REMAINING)
    try:
        recordlib.parse_record(kind, payload)
    except recordlib.RecordError:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
