#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import selectors
import signal
import secrets
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if os.fspath(ROOT) not in sys.path:
    sys.path.insert(0, os.fspath(ROOT))

from exploit.client import (  # noqa: E402
    AUTH_BEGIN,
    AUTH_FINISH,
    CANCEL,
    DISPATCH,
    HELLO,
    INSPECT,
    QUEUE,
    Broker,
    ExploitError,
    ProtocolError,
    U64_BE,
    run_exploit,
)


VULNERABLE = ROOT / "build" / "deadletterd"
FIXED = ROOT / "build" / "deadletterd-fixed"
ARTIFACTS = ROOT / "artifacts"
LISTEN_RE = re.compile(r"^LISTEN 127\.0\.0\.1:(\d+)$")


class LabError(RuntimeError):
    pass


class Server:
    def __init__(self, binary: Path):
        self.binary = binary.resolve()
        self.process: subprocess.Popen[str] | None = None
        self.port: int | None = None
        self.stderr = ""
        self.auth_token = secrets.token_hex(16)

    def __enter__(self) -> Server:
        env = os.environ.copy()
        env["LAB_MODE"] = "1"
        env["BROKER_AUTH_TOKEN"] = self.auth_token
        self.process = subprocess.Popen(
            [os.fspath(self.binary), "--port", "0"],
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
        assert self.process.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        try:
            ready = selector.select(timeout=3.0)
            if not ready:
                raise LabError(f"{self.binary.name} did not announce a listener")
            line = self.process.stdout.readline().strip()
            match = LISTEN_RE.fullmatch(line)
            if match is None:
                raise LabError(f"unexpected target startup output: {line!r}")
            self.port = int(match.group(1))
        except Exception:
            self.stop()
            raise
        finally:
            selector.close()
        return self

    def stop(self) -> None:
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=1.0)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1.0)
        _stdout, self.stderr = process.communicate(timeout=1.0)
        self.process = None

    def __exit__(self, *_exc: object) -> None:
        self.stop()


def check_mitigations(binary: Path) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, os.fspath(ROOT / "tools" / "checksec.py"), os.fspath(binary)],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LabError(f"mitigation checker returned invalid JSON: {result.stdout!r}") from exc
    if result.returncode != 0 or not payload.get("ok"):
        raise LabError(f"mitigation contract failed for {binary.name}: {payload}")
    return payload


def cleanup_proof(path: str | Path) -> None:
    proof = Path(path)
    proof.unlink(missing_ok=True)
    try:
        proof.parent.rmdir()
    except OSError:
        pass


def exploit_once(binary: Path, *, keep_proof: bool = False):
    with Server(binary) as server:
        assert server.port is not None
        result = run_exploit("127.0.0.1", server.port, binary)
    if not keep_proof:
        cleanup_proof(result.proof_path)
        proof = Path(result.proof_path)
        if proof.exists() or proof.parent.exists():
            raise LabError("proof cleanup did not remove the private temporary directory")
    return result


def write_evidence(name: str, payload: dict[str, object]) -> Path:
    ARTIFACTS.mkdir(exist_ok=True)
    path = ARTIFACTS / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def command_demo(binary: Path) -> int:
    mitigations = check_mitigations(binary)
    result = exploit_once(binary)
    payload = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "mitigations": mitigations["checks"],
        "proof_removed_after_verification": True,
        "result": asdict(result),
    }
    evidence = write_evidence("latest-demo.json", payload)
    print(
        f"execve confirmed in worker pid {result.worker_pid}; "
        f"PIE base {result.pie_base}; {result.elapsed_ms} ms"
    )
    print(f"evidence: {evidence.relative_to(ROOT)}")
    return 0


def expect_denied_without_pending_leak(binary: Path) -> None:
    with Server(binary) as server:
        assert server.port is not None
        with Broker("127.0.0.1", server.port) as broker:
            hello = broker.request(HELLO)
            if len(hello) != 9:
                raise LabError("baseline HELLO shape changed")
            job_id = U64_BE.unpack(broker.request(QUEUE, b"\x00control"))[0]
            broker.request(CANCEL, U64_BE.pack(job_id))
            try:
                broker.request(INSPECT)
            except ProtocolError as exc:
                if exc.status != 9:
                    raise LabError(f"baseline INSPECT returned status {exc.status}, expected 9")
            else:
                raise LabError("INSPECT leaked before the phase confusion was exercised")
            broker.request(AUTH_BEGIN)
            if len(broker.request(INSPECT)) != 256:
                raise LabError("AUTH_PENDING did not expose the stale job")


def expect_fixed_rejection(binary: Path) -> None:
    token = "f1edc0de00000001"
    before = set(Path("/tmp").glob(f"deadletter-{token}-*"))
    with Server(binary) as server:
        assert server.port is not None
        try:
            run_exploit("127.0.0.1", server.port, binary, token=token)
        except ProtocolError as exc:
            if exc.opcode != INSPECT or exc.status != 9:
                raise LabError(
                    f"fixed target failed at opcode 0x{exc.opcode:02x}, status {exc.status}"
                ) from exc
        else:
            raise LabError("fixed target accepted the exploit chain")
    after = set(Path("/tmp").glob(f"deadletter-{token}-*"))
    if after != before:
        raise LabError("failed fixed-build attempt left temporary proof state")


def expect_legitimate_diagnostic(binary: Path) -> None:
    with Server(binary) as server:
        assert server.port is not None
        with Broker("127.0.0.1", server.port) as broker:
            broker.request(HELLO)
            job_id = U64_BE.unpack(
                broker.request(QUEUE, b"\x00authenticated-control")
            )[0]
            broker.request(AUTH_BEGIN)
            phase = broker.request(AUTH_FINISH, server.auth_token.encode("ascii"))
            if phase != b"\x02":
                raise LabError("valid credentials did not enter AUTHENTICATED")
            if len(broker.request(INSPECT)) != 256:
                raise LabError("authenticated diagnostic returned the wrong object size")
            broker.request(CANCEL, U64_BE.pack(job_id))
            try:
                broker.request(INSPECT)
            except ProtocolError as exc:
                if exc.status != 8:
                    raise LabError(f"fixed unlink returned status {exc.status}, expected 8")
            else:
                raise LabError("fixed cancellation retained a diagnostic queue pointer")


def expect_legitimate_exec(binary: Path) -> None:
    with Server(binary) as server:
        assert server.port is not None
        with Broker("127.0.0.1", server.port) as broker:
            hello = broker.request(HELLO)
            worker_pid = U64_BE.unpack_from(hello, 1)[0]
            broker.request(AUTH_BEGIN)
            broker.request(AUTH_FINISH, server.auth_token.encode("ascii"))
            broker.request(QUEUE, b"\x01printf 'authorized:%s\\n' \"$$\"")
            broker.request(DISPATCH)
            output = broker.read_tail().decode("ascii", "strict").strip()
            if output != f"authorized:{worker_pid}":
                raise LabError(f"authenticated exec path returned {output!r}")


def check_runtime_gate(binary: Path) -> None:
    env = os.environ.copy()
    env.pop("LAB_MODE", None)
    result = subprocess.run(
        [os.fspath(binary), "--port", "0"],
        cwd=ROOT,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=2.0,
    )
    if result.returncode == 0 or "set LAB_MODE=1" not in result.stderr:
        raise LabError("target started without its explicit lab-mode gate")


def run_unit_tests() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        cwd=ROOT,
        check=False,
    )
    if result.returncode != 0:
        raise LabError("unit tests failed")


def command_check() -> int:
    run_unit_tests()
    check_runtime_gate(VULNERABLE)
    check_mitigations(VULNERABLE)
    check_mitigations(FIXED)
    expect_denied_without_pending_leak(VULNERABLE)
    expect_legitimate_diagnostic(FIXED)
    expect_legitimate_exec(FIXED)
    expect_fixed_rejection(FIXED)
    result = exploit_once(VULNERABLE)
    print(
        "check: unit, hardening, lab gate, auth control, fixed control, "
        f"and live exploit passed (pid {result.worker_pid})"
    )
    return 0


def command_reliability(binary: Path, runs: int) -> int:
    if runs < 2 or runs > 200:
        raise LabError("runs must be between 2 and 200")
    mitigations = check_mitigations(binary)
    results = []
    for index in range(runs):
        result = exploit_once(binary)
        results.append(result)
        print(f"[{index + 1:02d}/{runs:02d}] pid={result.worker_pid} pie={result.pie_base}")

    bases = {result.pie_base for result in results}
    chunks = {result.job_chunk for result in results}
    pids = {result.worker_pid for result in results}
    if len(bases) < 2:
        raise LabError("all fresh targets used one PIE base; ASLR evidence is inconclusive")
    if len(chunks) < 2:
        raise LabError("all fresh targets used one heap address; heap ASLR is inconclusive")
    if len(pids) != runs:
        raise LabError("worker PID reuse made process-identity evidence ambiguous")
    payload = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "runs": runs,
        "successes": len(results),
        "distinct_pie_bases": len(bases),
        "distinct_heap_chunks": len(chunks),
        "unique_worker_pids": len(pids),
        "proofs_removed_after_verification": True,
        "mitigations": mitigations["checks"],
        "results": [asdict(result) for result in results],
    }
    evidence = write_evidence("latest-reliability.json", payload)
    print(
        f"reliability: {len(results)}/{runs}; distinct PIE/heap addresses: "
        f"{len(bases)}/{len(chunks)}"
    )
    print(f"evidence: {evidence.relative_to(ROOT)}")
    return 0


def command_cleanup() -> int:
    removed = 0
    for proof_directory in Path("/tmp").glob("deadletter-*-*"):
        if proof_directory.is_symlink() or not proof_directory.is_dir():
            continue
        if proof_directory.stat().st_uid != os.getuid():
            continue
        proof = proof_directory / "proof"
        if proof.is_file() and not proof.is_symlink():
            proof.unlink()
            removed += 1
        try:
            proof_directory.rmdir()
        except OSError:
            pass
    for name in ("latest-demo.json", "latest-reliability.json"):
        artifact = ARTIFACTS / name
        if artifact.is_file():
            artifact.unlink()
            removed += 1
    try:
        ARTIFACTS.rmdir()
    except OSError:
        pass
    print(f"cleanup: removed {removed} generated evidence/proof file(s)")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="build verification for the deadletter lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo")
    demo.add_argument("--binary", type=Path, default=VULNERABLE)

    subparsers.add_parser("check")
    subparsers.add_parser("cleanup")

    reliability = subparsers.add_parser("reliability")
    reliability.add_argument("--binary", type=Path, default=VULNERABLE)
    reliability.add_argument("--runs", type=int, default=25)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "demo":
            return command_demo(args.binary.resolve())
        if args.command == "check":
            return command_check()
        if args.command == "reliability":
            return command_reliability(args.binary.resolve(), args.runs)
        if args.command == "cleanup":
            return command_cleanup()
        raise AssertionError(args.command)
    except (LabError, ExploitError, OSError, subprocess.SubprocessError) as exc:
        print(f"lab failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
