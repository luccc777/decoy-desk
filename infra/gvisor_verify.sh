#!/usr/bin/env bash
# Proves, on the VM, that the Decoy Desk sandbox enforces the containment rules under gVisor.
# Each test prints PASS or FAIL; nothing here reaches the internet from inside the sandbox.
set -uo pipefail

IMG=python:3.12-slim
docker pull -q "$IMG" >/dev/null
# Under gVisor, container processes live inside gVisor's own kernel. The process limit that works is
# --ulimit nproc, enforced by gVisor itself. --pids-limit counts gVisor's host threads instead, so it
# stays high as a host-side backstop (at 128 it kills the sandbox before nproc gets a chance).
BASE=(--runtime=runsc --network=none
      --memory=1g --memory-swap=1g --cpus=1 --pids-limit=1024
      --ulimit nproc=128:128 --ulimit nofile=256:256 --read-only --tmpfs /tmp:rw,size=64m
      --cap-drop=ALL --security-opt=no-new-privileges --user 1000:1000)
HARD=(--rm "${BASE[@]}")

check() { if [ "$2" = "0" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fi; }

# 1. The container runs on gVisor's kernel, not the VM's
# grep without -q reads the whole output: with pipefail, an early exit made docker fail on SIGPIPE now and then
docker run --rm --runtime=runsc alpine dmesg 2>/dev/null | grep -i gvisor >/dev/null
check "gVisor kernel (dmesg)" $?

# 2. Hardened flags work together: /tmp is writable, the rest is not
docker run "${HARD[@]}" "$IMG" python -c "
open('/tmp/ok','w').write('1')
try:
    open('/etc/x','w'); raise SystemExit(1)
except OSError:
    pass" >/dev/null
check "read-only root + tmpfs + non-root user" $?

# 3. No network
docker run "${HARD[@]}" "$IMG" python -c "
import socket
try:
    socket.create_connection(('1.1.1.1', 53), timeout=3); raise SystemExit(1)
except OSError:
    pass" >/dev/null
check "no network (--network=none)" $?

# 4. Fork bomb contained: either nproc blocks the fork (exit 0) or the memory cap kills it (137)
out=$(docker run "${HARD[@]}" "$IMG" sh -c 'exec python -c "$0"' "
import os, time
n = 0
try:
    for _ in range(400):
        if os.fork() == 0:
            time.sleep(3); os._exit(0)
        n += 1
except OSError:
    print('blocked at', n); raise SystemExit(0)
raise SystemExit(1)" 2>/dev/null)
rc=$?
case "$rc" in
  0)   check "fork bomb contained (${out:-ulimit nproc})" 0 ;;
  137) check "fork bomb contained (memory cap, exit 137)" 0 ;;
  *)   check "fork bomb contained (exit $rc)" 1 ;;
esac

# 5. Memory cap: allocating 2 GB under a 1 GB cap kills the process
docker run "${HARD[@]}" "$IMG" python -c "x = bytearray(2*1024*1024*1024)" >/dev/null 2>&1
rc=$?
[ "$rc" -ne 0 ]; check "memory cap (exit $rc)" $?

# 6. Wall clock: the orchestrator kills an overrunning job and removes it
docker run -d --name dd-clock "${BASE[@]}" "$IMG" python -c "while True: pass" >/dev/null
sleep 3; docker kill dd-clock >/dev/null 2>&1
docker rm -f dd-clock >/dev/null 2>&1
docker ps -a --format '{{.Names}}' | grep -q '^dd-clock$'
[ $? -ne 0 ]; check "killed on wall clock and removed" $?

# 7. Tracing runtime: file opens show up in the log, recorded outside the sandbox
rm -rf /var/log/runsc/*
docker run --rm --runtime=runsc-trace --network=none alpine sh -c "cat /etc/hostname >/dev/null" >/dev/null
grep -rqs "openat" /var/log/runsc/
check "syscalls recorded from outside (runsc-trace)" $?

echo "--- versions ---"
runsc --version | head -1
docker --version
