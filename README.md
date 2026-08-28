# deadletter

`deadletter` is a local x86-64 exploit lab built around a deliberately vulnerable
binary job broker. The exploit combines a protocol-state authorization error, a
heap use-after-free, a tcache reclaim, an ASLR disclosure, and a forged callback
object to obtain controlled `execve` in the vulnerable worker.

This is not a scanner. The included client drives the complete chain and verifies
that the pre-corruption worker PID is the PID later running `/bin/sh`.

## Attack path

1. `QUEUE` allocates a 256-byte job containing a `job_log` callback and pointers
   into its inline storage.
2. `CANCEL` frees the owner but leaves the same pointer on the pending queue.
3. `AUTH_BEGIN` enters `AUTH_PENDING`. A flawed ordinal check treats that state as
   at least as privileged as `AUTHENTICATED`.
4. `INSPECT` reads the freed job. The callback leak yields the PIE slide; the
   inline-storage pointer yields the heap chunk address.
5. `NOTE` creates a real note object in the same allocator class. Its 240-byte
   body begins where the stale job's callback lives, so the tcache reclaim gives
   control of every field needed for dispatch. The client confirms both glibc's
   safe-linked free-list value and the exact post-allocation overlap.
6. The replacement object points its callback at the broker's real `job_exec`
   path and its `program`/`argv` fields at strings forged inside the same chunk.
7. `DISPATCH` follows the stale queue pointer and makes the indirect call.
   `job_exec` replaces that worker with `/bin/sh -c <proof command>`.
8. The harness matches a random token in the socket output and proof file, and
   checks that the shell PID equals the worker PID disclosed by `HELLO`.

`job_exec` is also a legitimate authenticated job type; the exploit reaches it
through corrupted dispatch, not a planted `win()` function. The target is built
with PIE, ASLR, NX, full RELRO, stack protection, and fortify. The exploit parses
the matching ELF itself, binds its hash to `/proc/<worker>/exe`, derives runtime
addresses from the leak, and does not depend on pwntools or fixed addresses.

## Run it

The lab targets Linux x86-64. Run these commands from this directory. From
PowerShell, with Ubuntu on WSL:

```powershell
./demo.ps1
```

Or from a Linux/WSL shell:

```sh
make build
make demo
make check
make reliability
```

`make check` covers the protocol controls, legitimate authenticated diagnostics
and execution, the runtime lab gate, ELF mitigations, the live exploit, and the
`-DFIXED=1` negative control. `make reliability` launches 25 fresh ASLR instances
and writes the run record to
`artifacts/latest-reliability.json`.

The only build dependencies are GCC, GNU make, binutils (`readelf`), and Python 3.
On a minimal Ubuntu installation:

```sh
sudo apt-get install gcc libc6-dev make binutils python3
```

## Containment and reset

The server binds only to `127.0.0.1`, refuses to compile without `LAB_MODE=1`, and
refuses to start without both `LAB_MODE=1` and a per-run broker auth token. The
client accepts only a literal IPv4 loopback address. The harness uses a fixed
nonce-bearing proof command in a private mode-0700 temporary directory, kills the
server process group, and removes each proof directory after verification.

```sh
make reset
```

That removes the build plus the generated evidence and any remaining lab proof
files. It does not touch unrelated files in `/tmp` or the workspace.

The remediation build fixes both required conditions: cancellation unlinks the
pending entry before `free`, and diagnostic access requires the exact
`AUTHENTICATED` state.
