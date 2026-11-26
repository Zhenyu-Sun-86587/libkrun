"""Boot a two-vCPU Guest and check the host-controlled source freezer on KVM."""
import argparse
import array
import errno
import fcntl
import ctypes
import hashlib
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


def guest(library, root, address, standby, expected_helper):
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
    if expected_helper:
        digest = bytes.fromhex(expected_helper)
        set_option("krun_set_guest_identity_helper_v1", digest, ctypes.c_size_t(len(digest)))
    set_option("krun_set_control_socket", os.fsencode(address))
    set_option("krun_split_irqchip", False)
    set_option("krun_start_enter")


def receive_capture(address, session):
    def exact(sock, count):
        data = bytearray()
        while len(data) < count:
            part = sock.recv(count - len(data))
            assert part, "incomplete native capture export"
            data.extend(part)
        return bytes(data)

    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(str(address))
        sock.sendall(f"CAPTURE_EXPORT {session}\n".encode())
        header = bytearray()
        while not header.endswith(b"\n"):
            assert len(header) < 1024 * 1024, "capture header too large"
            header.extend(exact(sock, 1))
        assert header.startswith(b"OK "), header
        output = json.loads(header[3:])
        state = exact(sock, output["checkpoint_bytes"])
        descriptor = exact(sock, output["descriptor_bytes"])
        sizes = json.loads(descriptor)["backing_sizes"]
        assert len(sizes) == output["fd_count"] > 0
        seen = {}
        for key in sorted(sizes):
            body, ancillary, flags, _ = sock.recvmsg(1, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
            assert body == b"F" and len(ancillary) == 1 and not flags & socket.MSG_CTRUNC
            level, kind, raw = ancillary.pop()
            assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
            handles = array.array("i", raw)
            assert len(handles) == 1
            with os.fdopen(handles[0], "rb") as backing:
                seals = fcntl.fcntl(backing, fcntl.F_GET_SEALS)
                required = fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_WRITE
                assert seals & required == required
                assert fcntl.fcntl(backing, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
                st = os.fstat(backing.fileno())
                assert st.st_size == sizes[key] and key == f"ram-{st.st_dev:x}-{st.st_ino:x}"
                seen[key] = (st.st_ino, st.st_size)
        return output, hashlib.sha256(state).digest(), hashlib.sha256(descriptor).digest(), seen


def test(library, executable, standby, helper, wrong_digest, capture, helper_exits):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp, "root")
        root.mkdir()
        shutil.copy2(executable, root / "counters")
        address = Path(tmp, "control.sock")
        measured = []
        if helper:
            (root / "sbin").mkdir()
            (root / "etc").mkdir()
            shutil.copy2(helper, root / "sbin/smolvm-identity-helper")
            digest = hashlib.sha256(helper.read_bytes()).hexdigest()
            measured = ["--expected-helper", "ab" * 32 if wrong_digest else digest]
        if standby:
            for disk in ["data0", "archive"]:
                with (Path(tmp) / disk).open("wb") as image:
                    image.write(b"smolvm-standby-test\0")
                    image.truncate(4 * 1024 * 1024)
        proc = subprocess.Popen(
            [sys.executable, __file__, str(library), str(root), "--guest", str(address)] + (["--standby"] if standby else []) + measured,
            stdin=subprocess.DEVNULL,
            env={**os.environ, **({"SMOLVM_FORKABLE":"1"} if capture else {})},
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
            if helper_exits:
                for number in (1, 2):
                    session = f"{number} {secrets.token_hex(16)}"
                    start = time.monotonic()
                    assert command("PREPARE", session, "1000 5000") == f"OK {session} preparing 0"
                    phase(session, "armed")
                    armed = time.monotonic()
                    fixed = counts()
                    time.sleep(0.16)
                    assert counts() == fixed, "ordinary or nested PID namespace counter advanced"
                    phase(session, "failed_thawed", -errno.EPIPE)
                    wait_for(lambda: all(b > a for a, b in zip(fixed, counts())), 2)
                    thawed = time.monotonic()
                    assert thawed - armed < 3, "a dead helper outlived its bounded armed interval"
                    print(f"session={number} helper SIGKILL: frozen {len(fixed)} counters across 2 vCPUs, "
                          f"arm_ms={(armed-start)*1000:.1f} arm_to_counter_resume_ms={(thawed-armed)*1000:.1f}, "
                          "kernel reported failed_thawed EPIPE", flush=True)
                return
            if wrong_digest:
                session = f"1 {secrets.token_hex(16)}"
                assert command("PREPARE", session, "1000 2500").startswith("OK")
                phase(session, "failed_thawed", -129)
                start = counts()
                wait_for(lambda: all(b > a for a, b in zip(start, counts())))
                print("incorrect helper digest rejected before freeze; all counters running", flush=True)
                return
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
                assert disks == {i: {"read_only": ro, "capacity_bytes": 4 * 1024 * 1024, "managed_attachment": None}
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
                if helper:
                    session = f"8 {secrets.token_hex(16)}"
                    anchor = secrets.token_hex(16)
                    assert command("PREPARE", session, "2000 700").startswith("OK")
                    phase(session, "armed")
                    assert command("PARK", session, anchor).startswith("OK")
                    phase(session, "parked")
                    fixed = counts()
                    time.sleep(1)
                    assert fixed == counts(), "parked source thawed at its old preparation deadline"
                    assert command("PARK", session, secrets.token_hex(16)).startswith("ERR")
                    receipt = rpc(f"STANDBY_ENTER {session} managed")
                    assert receipt["source_disposition"] == "STANDBY" and receipt["mode"] == "managed", receipt
                    time.sleep(1)
                    assert counts() == fixed
                    assert wire(f"GUEST_GATE_RELEASE {session}").startswith("ERR EBUSY")
                    assert rpc(f"STANDBY_WAKE {session}")["source_disposition"] in ("WAKING", "RUNNING")
                    wait_for(lambda: rpc(f"STANDBY_QUERY {session}")["source_disposition"] == "RUNNING")
                    phase(session, "released")
                    wait_for(lambda: all(b > a for a, b in zip(fixed, counts())))
                    print("measured standby survived the old gate deadline and woke its original users", flush=True)
                if capture:
                    previous = set()
                    for seq, finish in [(5, "CAPTURE_FINISH"), (6, "CAPTURE_CANCEL")]:
                        token = f"{seq} {secrets.token_hex(16)}"
                        receipt = rpc(f"CAPTURE_PREPARE {token} raw")
                        assert receipt["source_disposition"] == "HELD" and not receipt["clone_ready"]
                        assert rpc(f"CAPTURE_PREPARE {token} raw") == rpc(f"CAPTURE_QUERY {token}") == receipt
                        assert wire(f"STANDBY_WAKE {hold}").startswith("ERR EBUSY")
                        assert wire(f"CAPTURE_FINISH {seq} {secrets.token_hex(16)} CONTINUE").startswith("ERR ESTALE")
                        assert wire("RESUME").startswith("ERR EBUSY")
                        start = (counts(), disk_counter())
                        with socket.socket(socket.AF_UNIX) as abandoned:
                            abandoned.connect(str(address))
                            abandoned.sendall(f"CAPTURE_EXPORT {token}\n".encode())
                        first = receive_capture(address, token)
                        assert first[0]["devices"] and first == receive_capture(address, token)
                        assert rpc(f"CAPTURE_FINISH {token} KEEP_HELD") == receipt
                        assert (counts(), disk_counter()) == start
                        assert previous < set(first[3]), "a later capture must preserve base inodes and add deltas"
                        previous = set(first[3])
                        decision = f"{finish} {token}" + (" CONTINUE" if finish == "CAPTURE_FINISH" else "")
                        assert rpc(decision)["source_disposition"] == "RUNNING"
                        assert rpc(decision) == rpc(f"CAPTURE_QUERY {token}")
                        if finish == "CAPTURE_FINISH":
                            assert first == receive_capture(address, token)
                        else:
                            assert wire(f"CAPTURE_EXPORT {token}").startswith("ERR EBUSY")
                        wait_for(lambda: all(b > a for a, b in zip(start[0], counts())) and disk_counter() > start[1])
                        print(f"held raw capture {seq}: {len(previous)} original sealed FDs, repeatable checkpoint, {finish}", flush=True)
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
    parser.add_argument("--capture", action="store_true", help="also export held vCPU/device state and sealed RAM")
    parser.add_argument("--identity-helper", type=Path, help="pin the actual static helper executable")
    failures = parser.add_mutually_exclusive_group()
    failures.add_argument("--wrong-digest", action="store_true", help="require pre-freeze measurement rejection")
    failures.add_argument("--helper-exits", action="store_true", help="require thaw when the measured test helper dies after arming")
    parser.add_argument("--expected-helper", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if (args.wrong_digest or args.helper_exits) and not args.identity_helper:
        parser.error("the measured helper failure cases require --identity-helper")
    if args.guest:
        guest(args.libkrun.resolve(), args.guest_path, args.guest, args.standby, args.expected_helper)
    else:
        test(args.libkrun.resolve(), args.guest_path.resolve(), args.standby or args.capture,
             args.identity_helper, args.wrong_digest, args.capture, args.helper_exits)
