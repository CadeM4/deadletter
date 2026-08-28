#!/usr/bin/env python3
"""Verify the mitigation contract for the deadletterd lab binary."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


class InspectionError(RuntimeError):
    pass


def run_readelf(binary: Path, *options: str) -> str:
    readelf = os.environ.get("READELF", "readelf")
    env = os.environ.copy()
    env["LC_ALL"] = "C"

    try:
        result = subprocess.run(
            [readelf, "--wide", *options, os.fspath(binary)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    except FileNotFoundError as exc:
        raise InspectionError(f"readelf not found: {readelf}") from exc

    if result.returncode != 0:
        reason = result.stderr.strip() or f"exit status {result.returncode}"
        raise InspectionError(f"readelf failed: {reason}")
    return result.stdout


def program_headers(text: str, kind: str) -> list[str]:
    flags: list[str] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[0] != kind:
            continue
        # With --wide, the columns between MemSiz and Align are the flags.
        flags.append("".join(fields[6:-1]))
    return flags


def result(ok: bool, detail: str) -> dict[str, object]:
    return {"ok": ok, "detail": detail}


def inspect(binary: Path) -> dict[str, object]:
    header = run_readelf(binary, "--file-header")
    segments = run_readelf(binary, "--program-headers")
    dynamic = run_readelf(binary, "--dynamic")
    symbols = run_readelf(binary, "--symbols")

    elf64 = re.search(r"^\s*Class:\s+ELF64\s*$", header, re.MULTILINE) is not None
    x86_64 = re.search(
        r"^\s*Machine:\s+.*(?:X86-64|x86-64).*$", header, re.MULTILINE
    ) is not None
    et_dyn = re.search(r"^\s*Type:\s+DYN\b", header, re.MULTILINE) is not None
    pie_flag = re.search(r"\(FLAGS_1\).*\bPIE\b", dynamic) is not None

    stack_flags = program_headers(segments, "GNU_STACK")
    load_flags = program_headers(segments, "LOAD")
    nonexec_stack = len(stack_flags) == 1 and "E" not in stack_flags[0]
    no_rwx_load = bool(load_flags) and all(
        not {"R", "W", "E"}.issubset(set(flags)) for flags in load_flags
    )

    has_relro = any(
        line.lstrip().startswith("GNU_RELRO") for line in segments.splitlines()
    )
    bind_now = (
        re.search(r"\bBIND_NOW\b", dynamic) is not None
        or re.search(r"\(FLAGS(?:_1)?\).*\bNOW\b", dynamic) is not None
    )

    canary_names = sorted(
        set(re.findall(r"\b(__stack_chk_(?:fail|guard))(?:@[\w.]+)?\b", symbols))
    )
    fortify_names = sorted(
        name
        for name in set(
            re.findall(r"\b(__[A-Za-z0-9_]+_chk)(?:@[\w.]+)?\b", symbols)
        )
        if not name.startswith("__stack_chk_")
    )

    checks = {
        "elf64": result(elf64, "ELF64" if elf64 else "expected ELF64"),
        "x86_64": result(x86_64, "x86-64" if x86_64 else "expected x86-64"),
        "pie": result(
            et_dyn and pie_flag,
            "ET_DYN with DF_1_PIE"
            if et_dyn and pie_flag
            else "expected ET_DYN with DF_1_PIE",
        ),
        "nonexec_stack": result(
            nonexec_stack,
            f"GNU_STACK={stack_flags[0]}"
            if len(stack_flags) == 1
            else f"expected one GNU_STACK, found {len(stack_flags)}",
        ),
        "no_rwx_load": result(
            no_rwx_load,
            "LOAD flags=" + ",".join(load_flags)
            if load_flags
            else "no LOAD segments found",
        ),
        "full_relro": result(
            has_relro and bind_now,
            f"GNU_RELRO={'yes' if has_relro else 'no'}, "
            f"BIND_NOW={'yes' if bind_now else 'no'}",
        ),
        "stack_canary": result(
            bool(canary_names),
            ",".join(canary_names) if canary_names else "no stack-canary symbol",
        ),
        "fortify": result(
            bool(fortify_names),
            ",".join(fortify_names) if fortify_names else "no fortified libc symbol",
        ),
    }

    return {
        "binary": os.fspath(binary),
        "ok": all(bool(check["ok"]) for check in checks.values()),
        "checks": checks,
    }


def emit(payload: dict[str, object], pretty: bool) -> None:
    if pretty:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="verify ELF hardening required by the local exploit lab"
    )
    parser.add_argument("binary", type=Path, help="ELF executable to inspect")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    args = parser.parse_args(argv)

    try:
        binary = args.binary.resolve(strict=True)
        if not binary.is_file():
            raise InspectionError(f"not a regular file: {binary}")
        payload = inspect(binary)
    except (InspectionError, OSError) as exc:
        emit(
            {
                "binary": os.fspath(args.binary),
                "ok": False,
                "error": str(exc),
            },
            args.pretty,
        )
        return 2

    emit(payload, args.pretty)
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
