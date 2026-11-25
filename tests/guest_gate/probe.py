"""Boot a two-vCPU Guest and check the host-controlled source freezer on KVM."""
import argparse
import ctypes
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time


def guest(library, root, address):
    api = ctypes.CDLL(str(library))
    ctx = api.krun_create_ctx()
    if ctx < 0:
        raise OSError(-ctx, "krun_create_ctx")

    def set_option(name, *args):
        status = getattr(api, name)(ctx, *args)
        if status < 0:
            raise OSError(-status, name)

    set_option("krun_set_vm_config", 2, 512)
    set_option("krun_add_virtio_console_default", 0, 1, 2)
    set_option("krun_add_virtiofs3", b"/dev/root", os.fsencode(root), ctypes.c_uint64(0), False)
    set_option("krun_set_workdir", b"/")
    empty = (ctypes.c_char_p * 1)(None)
    set_option("krun_set_exec", b"/counters", empty, empty)
    set_option("krun_enable_guest_gate_v1")
    set_option("krun_set_control_socket", os.fsencode(address))
    set_option("krun_split_irqchip", False)
    set_option("krun_start_enter")


def test(library, executable):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp, "root")
        root.mkdir()
        shutil.copy2(executable, root / "counters")
        address = Path(tmp, "control.sock")
        proc = subprocess.Popen(
            [sys.executable, __file__, str(library), str(root), "--guest", str(address)],
            stdin=subprocess.DEVNULL,
        )
        def command(verb, session, args=""):
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(2)
                sock.connect(str(address))
                sock.sendall(f"GUEST_GATE_{verb} {session} {args}\n".encode())
                return sock.makefile().readline().strip()

        def counts():
            return [struct.unpack("<Q", (root / f"counter-{index}").read_bytes())[0]
                    for index in range(3)]

        def wait_for(predicate, seconds=10):
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                if proc.poll() is not None:
                    raise RuntimeError(f"Guest exited with status {proc.returncode}")
                try:
                    value = predicate()
                except (FileNotFoundError, ConnectionRefusedError, struct.error):
                    value = False
                if value:
                    return value
                time.sleep(0.02)
            raise RuntimeError("Guest state transition timed out")

        def phase(session, name, error=0):
            expected = f"OK {session} {name} {error}"
            wait_for(lambda: command("QUERY", session) == expected)

        try:
            wait_for(lambda: min(counts()) >= 2, 30)
            for number, decision, terminal in [(1, "RELEASE", "released"),
                                                (2, "ABORT", "aborted"),
                                                (3, None, "expired_thawed")]:
                session = f"{number} {secrets.token_hex(16)}"
                hold_ms = 750 if decision is None else 2500
                prepare = command("PREPARE", session, f"1000 {hold_ms}")
                assert prepare == f"OK {session} preparing 0", prepare
                phase(session, "armed")
                fixed = counts()
                time.sleep(0.16)
                assert fixed == counts(), "userspace advanced while the gate was armed"
                assert command("QUERY", f"{number} {secrets.token_hex(16)}").startswith("ERR ESTALE")
                assert command("PREPARE", session, f"1000 {hold_ms}") == f"OK {session} armed 0"
                if decision:
                    assert command(decision, session).startswith(f"OK {session} ")
                phase(session, terminal, 0 if decision else -110)
                wait_for(lambda: all(b > a for a, b in zip(fixed, counts())))
                print(f"{terminal}: three pinned counters stopped and then resumed", flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("libkrun", type=Path)
    parser.add_argument("guest_path", type=Path)
    parser.add_argument("--guest", type=Path, metavar="CONTROL_SOCKET", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.guest:
        guest(args.libkrun.resolve(), args.guest_path, args.guest)
    else:
        test(args.libkrun.resolve(), args.guest_path.resolve())
