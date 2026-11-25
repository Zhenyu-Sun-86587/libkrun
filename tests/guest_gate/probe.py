"""Boot a two-vCPU Guest and check the host-controlled source freezer on KVM."""
import argparse
import ctypes
import json
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


def guest(library, root, address, standby):
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
    if standby:
        for label, readonly in [("data0", False), ("archive", True)]:
            set_option("krun_add_disk", label.encode(), os.fsencode(root.parent / label), readonly)
    set_option("krun_set_workdir", b"/")
    empty = (ctypes.c_char_p * 1)(None)
    set_option("krun_set_exec", b"/counters", empty, empty)
    set_option("krun_enable_guest_gate_v1")
    set_option("krun_set_control_socket", os.fsencode(address))
    set_option("krun_split_irqchip", False)
    set_option("krun_start_enter")


def test(library, executable, standby):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp, "root")
        root.mkdir()
        shutil.copy2(executable, root / "counters")
        address = Path(tmp, "control.sock")
        if standby:
            for disk in ["data0", "archive"]:
                with (Path(tmp) / disk).open("wb") as image:
                    image.write(b"smolvm-standby-test\0")
                    image.truncate(4 * 1024 * 1024)
        proc = subprocess.Popen(
            [sys.executable, __file__, str(library), str(root), "--guest", str(address)] + (["--standby"] if standby else []),
            stdin=subprocess.DEVNULL,
        )
        def wire(line):
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(2)
                sock.connect(str(address))
                sock.sendall((line + "\n").encode())
                return sock.makefile().readline().strip()

        def command(verb, session, args=""):
            return wire(f"GUEST_GATE_{verb} {session} {args}")

        def counter_records():
            return [struct.unpack("<QQ", (root / f"counter-{index}").read_bytes())
                    for index in range(3)]

        def counts():
            return [record[0] for record in counter_records()]

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
            if standby:
                def rpc(line):
                    response = wire(line)
                    assert response.startswith("OK "), response
                    return json.loads(response[3:])

                devices = rpc("CAPTURE_INVENTORY")["devices"]
                disks = {d["device_id"]: d["block"] for d in devices if d["block"]}
                assert disks == {i: {"read_only": ro, "capacity_bytes": 4 * 1024 * 1024}
                                 for i, ro in [("data0", False), ("archive", True)]}, disks
                assert len({d["mmio_address"] for d in devices}) == len(devices)
                assert any(d["device_id"] == "guest-gate" for d in devices)

                def disk_counter():
                    with (Path(tmp) / "data0").open("rb", buffering=0) as image:
                        image.seek(512)
                        return struct.unpack("<Q", image.read(8))[0]

                wait_for(lambda: disk_counter() > 0)
                hold = f"4 {secrets.token_hex(16)}"
                receipt = rpc(f"STANDBY_ENTER {hold} raw")
                assert receipt["source_disposition"] == "STANDBY" and receipt["clone_ready"] is False, receipt
                before = counter_records()
                block_before = disk_counter()
                assert wire("RESUME").startswith("ERR EBUSY")
                assert wire(f"STANDBY_WAKE 4 {secrets.token_hex(16)}").startswith("ERR ESTALE")
                time.sleep(2)
                assert rpc(f"STANDBY_QUERY {hold}") == receipt
                assert rpc(f"STANDBY_ENTER {hold} raw") == receipt
                assert before == counter_records() and block_before == disk_counter()
                woke = rpc(f"STANDBY_WAKE {hold}")
                assert woke["source_disposition"] == "RUNNING"
                assert rpc(f"STANDBY_WAKE {hold}") == woke
                wait_for(lambda: all(b > a[0] for a, b in zip(before, counts())) and disk_counter() > block_before)
                delta = (counter_records()[0][1] - before[0][1]) / 1e6
                assert 0 < delta < 1500, f"Guest monotonic clock advanced {delta:.2f} ms during stand-by"
                print(f"raw standby held three counters and a writable disk for 2 s; Guest elapsed {delta:.2f} ms", flush=True)
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
    parser.add_argument("--standby", action="store_true", help="exercise raw standby with two test disks")
    args = parser.parse_args()
    if args.guest:
        guest(args.libkrun.resolve(), args.guest_path, args.guest, args.standby)
    else:
        test(args.libkrun.resolve(), args.guest_path.resolve(), args.standby)
