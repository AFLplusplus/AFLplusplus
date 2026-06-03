#!/usr/bin/env python3
"""
Simple wrapper class for afl-showmap streaming mode.

Usage:
    with AflShowmapStreaming("./afl-showmap", "./target", ["arg1"]) as showmap:
        status, crash_signal, edges = showmap.get_coverage(b"test input")
        print(f"Status: {status.name}, hit {len(edges)} edges")
        if crash_signal:
            print(f"Crashed with signal: {crash_signal.name}")

        # Batch processing
        results = showmap.get_coverage_batch([b"input1", b"input2"])
        for status, crash_signal, edges in results:
            print(f"{status.name}: {len(edges)} edges")
"""

import os
import signal
import struct
import subprocess
import sys
from enum import IntEnum
from pathlib import Path


class ExitStatus(IntEnum):
    """Exit status from streaming protocol (bits [0:1] of status field)."""

    EXITED = 0   # Normal exit
    TIMEOUT = 1  # Execution timed out
    CRASH = 2    # Target crashed


# Status field layout (u16):
#   bits [0:1]:  exit status (0=exited, 1=timeout, 2=crash)
#   bits [2:7]:  reserved (must be 0)
#   bits [8:15]: WEXITSTATUS (when exited) or WTERMSIG (when crash)

# Masks for status field parsing
_STATUS_EXIT_MASK = 0x0003      # bits [0:1]
_STATUS_RESERVED_MASK = 0x00FC  # bits [2:7] (must be 0)
_STATUS_INFO_SHIFT = 8          # bits [8:15]


class AflShowmapStreaming:
    """Minimal wrapper for afl-showmap -S streaming mode (sync)."""

    def __init__(
        self,
        afl_showmap: "str | Path",
        target: "str | Path",
        target_args: "list[str] | None" = None,
        timeout_ms: int = 1000,
    ):
        cmd = [str(afl_showmap), "-S", "-t", str(timeout_ms), "--", str(target)]
        if target_args:
            cmd.extend(target_args)
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "AFL_QUIET": "1"},
        )

    def get_coverage(
        self, data: bytes
    ) -> "tuple[ExitStatus, signal.Signals | None, list[tuple[int, int]]]":
        """Send input, get coverage result.

        Returns:
            (exit_status, crash_signal, edges) where edges is list of (edge_offset, hit_count).
        """
        self._send(data)
        return self._recv()

    def get_coverage_batch(
        self, inputs: "list[bytes]"
    ) -> "list[tuple[ExitStatus, signal.Signals | None, list[tuple[int, int]]]]":
        """Process multiple inputs, return list of (exit_status, crash_signal, edges) tuples."""
        return [self.get_coverage(data) for data in inputs]

    def _send(self, data: bytes) -> None:
        """Send a test case: [u32 length][data]."""
        assert self._proc.stdin
        self._proc.stdin.write(struct.pack("<I", len(data)) + data)
        self._proc.stdin.flush()

    def _recv(self) -> "tuple[ExitStatus, signal.Signals | None, list[tuple[int, int]]]":
        """Receive one response from the streaming protocol.

        Wire format:
            [u16 status][u32 count][{u32 edge_idx, u8 hit_ctr} * count]
            [u32 stdout_len][u8 stdout_data*][u32 stderr_len][u8 stderr_data*]

        Returns:
            (exit_status, crash_signal, edges) where:
            - exit_status: ExitStatus enum value
            - crash_signal: signal.Signals if crash, None otherwise
            - edges: list of (edge_offset, hit_count) tuples
        """
        status_raw = struct.unpack("<H", self._read_exactly(2))[0]

        # Check reserved bits — if non-zero, protocol has changed
        reserved = status_raw & _STATUS_RESERVED_MASK
        if reserved != 0:
            raise RuntimeError(
                f"Protocol mismatch: reserved status bits are non-zero ({reserved:#x}). "
                f"Update this client to match the new afl-showmap protocol."
            )

        exit_status = ExitStatus(status_raw & _STATUS_EXIT_MASK)
        info_value = status_raw >> _STATUS_INFO_SHIFT
        crash_signal = (
            signal.Signals(info_value) if exit_status == ExitStatus.CRASH and info_value else None
        )

        edge_count = struct.unpack("<I", self._read_exactly(4))[0]
        edge_data = self._read_exactly(edge_count * 5)
        edges = [
            struct.unpack_from("<IB", edge_data, i * 5) for i in range(edge_count)
        ]

        # Read stdout/stderr LV fields (currently always length=0)
        stdout_len = struct.unpack("<I", self._read_exactly(4))[0]
        if stdout_len > 0:
            self._read_exactly(stdout_len)  # discard
        stderr_len = struct.unpack("<I", self._read_exactly(4))[0]
        if stderr_len > 0:
            self._read_exactly(stderr_len)  # discard

        return exit_status, crash_signal, edges

    def _read_exactly(self, n: int) -> bytes:
        """Read exactly n bytes from stdout."""
        assert self._proc.stdout
        data = b""
        while len(data) < n:
            chunk = self._proc.stdout.read(n - len(data))
            if not chunk:
                raise EOFError(f"Expected {n} bytes, got {len(data)}")
            data += chunk
        return data

    def close(self) -> None:
        """Close the streaming connection and verify afl-showmap exited cleanly."""
        assert self._proc.stdin
        # Send: [u32 length=0] — signals EOF
        self._proc.stdin.write(struct.pack("<I", 0))
        self._proc.stdin.flush()
        self._proc.stdin.close()

        exit_code = self._proc.wait()
        if exit_code != 0:
            stderr = self._proc.stderr.read().decode() if self._proc.stderr else ""
            raise RuntimeError(f"afl-showmap failed (exit {exit_code}): {stderr}")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _run_demo(afl_showmap: Path, target: Path, target_args: "list[str]") -> None:
    """Run demo showing wrapper usage."""
    with AflShowmapStreaming(afl_showmap, target, target_args) as showmap:
        # Single input
        print("Single:")
        status, crash_signal, edges = showmap.get_coverage(b"AAAA")
        sig_info = f", signal={crash_signal.name}" if crash_signal else ""
        print(f"  b'AAAA': {status.name}{sig_info}, {len(edges)} edges")

        # Batch
        print("\nBatch:")
        inputs = [b"BBBB", b"CCCC", b"test"]
        results = showmap.get_coverage_batch(inputs)
        for inp, (status, crash_signal, edges) in zip(inputs, results):
            sig_info = f", signal={crash_signal.name}" if crash_signal else ""
            print(f"  {inp!r}: {status.name}{sig_info}, {len(edges)} edges")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <afl-showmap> <target> [target_args...]")
        sys.exit(1)

    afl_showmap = Path(sys.argv[1])
    target = Path(sys.argv[2])
    target_args = sys.argv[3:]

    _run_demo(afl_showmap, target, target_args)
