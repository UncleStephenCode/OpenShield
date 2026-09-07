#!/usr/bin/env python3
"""Flush complete log lines promptly while enforcing a byte and memory bound.

After the first line that cannot fit, emit one marker and consume the remaining
input without retaining it. Draining preserves the producer's actual exit
status instead of terminating it early with a broken pipe.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import BinaryIO


MARKER = b"[performance CI smoke: output truncated]\n"
MAX_LIMIT_BYTES = 16 * 1024 * 1024
READ_BYTES = 64 * 1024


def byte_limit(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("byte limit must be a positive decimal integer")
    limit = int(value)
    if not len(MARKER) <= limit <= MAX_LIMIT_BYTES:
        raise argparse.ArgumentTypeError(
            f"byte limit must be between {len(MARKER)} and {MAX_LIMIT_BYTES}"
        )
    return limit


def copy_bounded_lines(source_fd: int, destination: BinaryIO, limit: int) -> None:
    remaining = limit - len(MARKER)
    pending = bytearray()
    truncated = False
    while True:
        # BufferedReader.read(READ_BYTES) may wait to fill its buffer. os.read
        # returns whatever is available, even while the producer keeps stdin
        # open during a long phase. Never accumulate more than the byte budget.
        chunk = os.read(source_fd, READ_BYTES)
        if not chunk:
            break
        if truncated:
            continue
        offset = 0
        while offset < len(chunk):
            newline = chunk.find(b"\n", offset)
            end = len(chunk) if newline < 0 else newline + 1
            fragment = chunk[offset:end]
            # Like awk print, an unterminated final line receives a newline.
            required = len(pending) + len(fragment) + (1 if newline < 0 else 0)
            if required > remaining:
                destination.write(MARKER)
                destination.flush()
                pending.clear()
                truncated = True
                break
            pending.extend(fragment)
            offset = end
            if newline >= 0:
                destination.write(pending)
                destination.flush()
                remaining -= len(pending)
                pending.clear()
    if pending:
        pending.append(10)
        destination.write(pending)
        destination.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit-bytes", type=byte_limit, required=True)
    arguments = parser.parse_args()
    copy_bounded_lines(sys.stdin.fileno(), sys.stdout.buffer, arguments.limit_bytes)


if __name__ == "__main__":
    main()
