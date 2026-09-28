"""
Adversarial skill implementing deliberate attack attempts against container containment boundaries.
Each vector must be contained by the OCI sandbox (namespaces, seccomp, no-new-privileges, cgroups, limits).
"""

import ctypes
import os
import socket
import sys
from typing import Any, Dict


def execute_skill(context: Dict[str, Any], parameters: Dict[str, Any]) -> Dict[str, Any]:
    attack_type = parameters.get("attack_type", "none")

    # 1. Host file exfiltration attempt
    if attack_type == "ssh_read":
        targets = [
            os.path.expanduser("~/.ssh/id_rsa"),
            "/root/.ssh/id_rsa",
            "/home/masouser/.ssh/id_rsa",
            "/etc/shadow",
            "/host/etc/passwd",
        ]
        leaked_files = []
        for t in targets:
            try:
                with open(t, "r") as f:
                    leaked_files.append(t)
            except Exception:
                pass
        if leaked_files:
            return {"status": "BREACH", "attack": attack_type, "leaked": leaked_files}
        return {"status": "CONTAINED", "attack": attack_type, "message": "Host filesystem inaccessible"}

    # 2. Raw network connection attempt (in offline mode)
    if attack_type == "socket_connect":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(("127.0.0.1", 5678))
            return {"status": "BREACH", "attack": attack_type, "message": "Network socket connected"}
        except Exception as e:
            return {"status": "CONTAINED", "attack": attack_type, "error": str(e)}

    # 3. Denied syscall: ptrace
    if attack_type == "ptrace_syscall":
        libc = ctypes.CDLL(None)
        try:
            # ptrace(PTRACE_TRACEME, 0, 0, 0)
            res = libc.ptrace(0, 0, 0, 0)
            if res == 0:
                return {"status": "BREACH", "attack": attack_type, "message": "ptrace succeeded"}
        except Exception as e:
            return {"status": "CONTAINED", "attack": attack_type, "error": str(e)}
        return {"status": "CONTAINED", "attack": attack_type, "errno": ctypes.get_errno()}

    # 4. Denied syscall: mount
    if attack_type == "mount_syscall":
        libc = ctypes.CDLL(None)
        try:
            res = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
            if res == 0:
                return {"status": "BREACH", "attack": attack_type, "message": "mount succeeded"}
        except Exception as e:
            return {"status": "CONTAINED", "attack": attack_type, "error": str(e)}
        return {"status": "CONTAINED", "attack": attack_type, "errno": ctypes.get_errno()}

    # 5. Denied syscall: bpf
    if attack_type == "bpf_syscall":
        libc = ctypes.CDLL(None)
        try:
            # syscall 321 (SYS_bpf on x86_64)
            res = libc.syscall(321, 0, None, 0)
            if res >= 0:
                return {"status": "BREACH", "attack": attack_type, "message": "bpf succeeded"}
        except Exception as e:
            return {"status": "CONTAINED", "attack": attack_type, "error": str(e)}
        return {"status": "CONTAINED", "attack": attack_type, "errno": ctypes.get_errno()}

    # 6. Privilege escalation: setuid
    if attack_type == "setuid_escalation":
        try:
            os.setuid(0)
            return {"status": "BREACH", "attack": attack_type, "message": "Escalated to root"}
        except Exception as e:
            return {"status": "CONTAINED", "attack": attack_type, "error": str(e)}

    # 7. Memory exhaustion / allocation bomb
    if attack_type == "memory_bomb":
        # Attempt to allocate 700 MiB (greater than 512m container memory limit)
        # This will trigger kernel OOM kill of the worker container
        large_alloc = bytearray(700 * 1024 * 1024)
        return {"status": "BREACH", "attack": attack_type, "allocated_bytes": len(large_alloc)}

    # 8. PID limit / fork bomb attempt
    if attack_type == "fork_bomb":
        import threading
        spawned = 0
        try:
            threads = []
            for _ in range(200):
                t = threading.Thread(target=lambda: os.path.exists("/workspace"))
                t.start()
                threads.append(t)
                spawned += 1
            for t in threads:
                t.join(timeout=1.0)
            return {"status": "BREACH", "attack": attack_type, "threads_spawned": spawned}
        except Exception as e:
            return {"status": "CONTAINED", "attack": attack_type, "threads_spawned": spawned, "error": str(e)}

    # 9. Oversized output attempt (host disk fill DoS)
    if attack_type == "oversized_output":
        # 15 MiB string (exceeds default 10 MiB limit)
        huge_str = "A" * (15 * 1024 * 1024)
        return {"status": "OVERSIZED", "attack": attack_type, "data": huge_str}

    return {"status": "UNKNOWN_ATTACK", "attack": attack_type}
