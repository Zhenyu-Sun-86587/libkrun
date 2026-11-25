"""Restore a real parked x86 Guest from retained FDs into a separate VMM."""
import argparse
import array
import ctypes as ct
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

SOURCE_ID = "0102030405060708090a0b0c0d0e0f10"
ROWS = re.compile(rb"IDENTITY_TICK (\d+) (\d+) ([\w-]+) ([a-f0-9]{32})")


class Layer(ct.Structure):
    _fields_ = [("resource_id", ct.c_char_p), ("fd", ct.c_int), ("format", ct.c_uint32)]


class Block(ct.Structure):
    _fields_ = [("size", ct.c_uint32), ("version", ct.c_uint32),
                *((key, ct.c_char_p) for key in ("attachment", "device", "role", "volume", "generation", "head", "grant")),
                ("epoch", ct.c_uint64), ("capacity", ct.c_uint64),
                ("layers", ct.POINTER(Layer)), ("count", ct.c_size_t)]


class Tap(ct.Structure):
    _fields_ = [("size",ct.c_uint32),("version",ct.c_uint32),("device",ct.c_char*64),
                ("features",ct.c_uint32),("mtu",ct.c_uint16),("queues",ct.c_uint16),("header",ct.c_uint16),
                ("mac",ct.c_ubyte*6),("digest",ct.c_ubyte*32)]


def boot(args, config):
    api = ct.CDLL(str(args.lib))
    ctx = api.krun_create_ctx()
    def call(name, *values):
        rc = getattr(api, name)(ctx, *values)
        if rc < 0:
            raise OSError(-rc, name)
    if "tap" in config:
        tap=config["tap"]
        spec=Tap(ct.sizeof(Tap),1,b"net0",3,1500,1,12,
                 (ct.c_ubyte*6).from_buffer_copy(bytes.fromhex(tap["mac"])),
                 (ct.c_ubyte*32).from_buffer_copy(bytes.fromhex(tap["digest"])))
        call("krun_add_net_tap_fd_v1",ct.byref(spec),tap["fd"])
        os.close(tap["fd"])
    call("krun_set_vm_config", 2, 512)
    call("krun_add_virtio_console_default", 0, 1, 2)
    call("krun_set_kernel_console", b"hvc0")
    disk = Path(config["disk"])
    fd = os.open(disk, os.O_RDONLY)
    layer = Layer(b"root-base", fd, 0)
    block = Block(ct.sizeof(Block), 1, b"attach-root", b"root0", b"root", b"volume-root",
                  b"root-base", None, None, config.get("epoch", 1), disk.stat().st_size,
                  ct.pointer(layer), 1)
    call("krun_attach_block_set_v1", ct.byref(block), ct.c_size_t(1))
    os.close(fd)
    call("krun_set_root_disk_remount", b"/dev/vda", b"ext4", b"ro,noload")
    call("krun_set_workdir", b"/")
    empty = (ct.c_char_p * 1)(None)
    call("krun_set_exec", b"/counter", empty, empty)
    call("krun_set_guest_identity_helper_v1", bytes.fromhex(config["helper"]), ct.c_size_t(32))
    if "restore" in config:
        descriptor = bytes.fromhex(config["descriptor"])
        fds = (ct.c_int * len(config["fds"]))(*config["fds"])
        call("krun_set_snapshot", os.fsencode(config["restore"]))
        call("krun_set_diskless_snapshot_ram_v1", descriptor, ct.c_size_t(len(descriptor)), fds, ct.c_size_t(len(fds)))
        call("krun_set_guest_target_authority_v1", config["authority"], bytes.fromhex(config["anchor"]),
             bytes.fromhex(config["context"]), ct.c_uint64(config["epoch"]))
    call("krun_set_control_socket", os.fsencode(config["control"]))
    call("krun_split_irqchip", False)
    call("krun_start_enter")


def until(test, seconds=10):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            last = test()
        except (FileNotFoundError, ConnectionRefusedError):
            last = None
        if last:
            return last
        time.sleep(.02)
    raise RuntimeError(f"Guest failed to reach expected state ({last!r})")


def wire(path, line):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(str(path))
        sock.sendall((line + "\n").encode())
        return sock.makefile().readline().strip()


def export_point(path, token):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(str(path))
        sock.sendall(f"CAPTURE_EXPORT {token}\n".encode())
        with sock.makefile("rb", buffering=0) as stream:
            header = stream.readline()
            assert header.startswith(b"OK "), header
            header = json.loads(header[3:])
            assert header["export"] == "parked", header
            def exact(size):
                result = bytearray()
                while len(result) < size:
                    chunk = stream.read(size - len(result))
                    assert chunk
                    result.extend(chunk)
                return bytes(result)
            checkpoint = exact(header["checkpoint_bytes"])
            descriptor = exact(header["descriptor_bytes"])
            fds = []
            for key in sorted(json.loads(descriptor)["backing_sizes"]):
                payload, ancillary, flags, _ = sock.recvmsg(1, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
                assert payload == b"F" and len(ancillary) == 1 and not flags & socket.MSG_CTRUNC
                level, kind, raw = ancillary[0]
                assert level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS and len(raw) == 4
                fd = array.array("i", raw)[0]
                stat = os.fstat(fd)
                assert key == f"ram-{stat.st_dev:x}-{stat.st_ino:x}" and fcntl.fcntl(fd, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE
                fds.append(fd)
            return checkpoint, descriptor, fds


def run(args, directory):
    root = directory / "tree"
    for sub in ("sbin", "dev", "tmp", "run", "proc", "sys", "etc"):
        (root / sub).mkdir(parents=True)
    shutil.copy2(args.counter, root / "counter")
    shutil.copy2(args.helper, root / "sbin/smolvm-identity-helper")
    disk = directory / "base.ext4"
    with disk.open("wb") as output:
        output.truncate(32 * 1024 * 1024)
    subprocess.run(["mke2fs", "-q", "-t", "ext4", "-d", str(root), str(disk)], check=True)
    disk.chmod(0o400)
    basic = {"helper":hashlib.sha256(args.helper.read_bytes()).hexdigest(), "disk":str(disk)}
    processes, handles = [], []
    def address(number):
        return f"10.{90+number}.0."
    def mac(number):
        return bytes([2,0,0,0,0,number])
    def new_tap(number):
        interface = f"gate{number}"
        fd=os.open("/dev/net/tun",os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC)
        fcntl.ioctl(fd,0x400454ca,struct.pack("16sH22x",interface.encode(),0x5002))
        fcntl.ioctl(fd,0x400454d8,struct.pack("i",12))
        subprocess.run(["ip","addr","add",address(number)+"1/24","dev",interface],check=True)
        subprocess.run(["ip","link","set",interface,"up"],check=True)
        return {"fd":fd,"mac":mac(number).hex(),"digest":secrets.token_hex(32)}
    def ping(number):
        return subprocess.run(["ping","-n","-q","-I",f"gate{number}","-c","1","-W","1",address(number)+"2"],
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0

    def launch(name, config, passed=()):
        path = directory / (name + ".sock")
        log = directory / (name + ".log")
        cfg = directory / (name + ".json")
        if args.network:
            tap=new_tap(config.get("epoch",1))
            config={**config,"tap":tap}
            passed=(*passed,tap["fd"])
        cfg.write_text(json.dumps({**basic, **config, "control":str(path)}))
        with log.open("wb") as out:
            proc = subprocess.Popen([sys.executable, __file__, str(args.lib), "--boot", str(cfg)],
                                    pass_fds=passed, stdin=subprocess.DEVNULL, stdout=out, stderr=out,
                                    env={**os.environ, "SMOLVM_FORKABLE":"1", "RUST_LOG":"error"})
        if args.network:
            os.close(tap["fd"])
        processes.append(proc)
        def rows():
            if proc.poll() is not None:
                raise RuntimeError(f"{name} exited: {log.read_bytes()[-3000:]!r}")
            return ROWS.findall(log.read_bytes())
        return path, rows
    authorities = []
    def capture(control, number, name):
        token = f"{number} {secrets.token_hex(16)}"
        anchor = secrets.token_bytes(16)
        def gate(verb, tail=""):
            return wire(control, f"GUEST_GATE_{verb} {token} {tail}")
        assert gate("PREPARE", "2500 5000").startswith("OK")
        until(lambda: " armed 0" in gate("QUERY"))
        if args.network:
            assert ping(number), "the kernel must still answer while only userspace is frozen"
        assert gate("PARK_NETWORK" if args.network else "PARK", anchor.hex()).startswith("OK")
        until(lambda: " parked 0" in gate("QUERY"))
        if args.network:
            assert not ping(number), "parked Guest answered through an open host TAP"
        assert '"source_disposition":"STANDBY"' in wire(control, f"STANDBY_ENTER {token} managed")
        prepare = wire(control, f"CAPTURE_PREPARE {token} parked")
        assert '"source_disposition":"HELD"' in prepare, prepare
        data, descriptor, backings = export_point(control, token)
        handles.extend(backings)
        restore = directory / name
        restore.mkdir()
        (restore / "checkpoint.bin").write_bytes(data)
        assert '"source_disposition":"STANDBY"' in wire(control, f"CAPTURE_FINISH {token} RETURN_STANDBY")
        return token, (restore, descriptor, backings, anchor, number)

    def restored(name, point, epoch, hostname, *, fail=False):
        restore, descriptor, backings, anchor, source_number = point
        authority, worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        authorities.append(authority)
        authority.settimeout(3)
        context, nonce, machine = secrets.token_bytes(32), secrets.token_bytes(16), secrets.token_bytes(16)
        hostname = hostname.encode()
        frame = (b"SGI1\x01\0\0\0" + nonce + epoch.to_bytes(8, "little") + context + secrets.token_bytes(32)
                 + machine + bytes([len(hostname)]) + hostname).ljust(192, b"\0")
        if args.network:
            ip=socket.inet_aton
            tail=(b"NET1"+bytes([1,24,24,0])+mac(source_number)+mac(epoch)+ip(address(source_number)+"2")+
                  ip(address(epoch)+"2")+ip(address(source_number)+"1")+ip(address(epoch)+"1")+ip(address(epoch)+"1")+
                  b"eth0".ljust(16,b"\0")+bytes(8))
            frame=b"SGI2\x02\0\0\0"+frame[8:]+tail
        ctl, rows = launch(name, {"restore": str(restore), "fds": backings, "descriptor": descriptor.hex(),
                                 "authority": worker.fileno(), "context": context.hex(), "epoch": epoch,
                                 "anchor": anchor.hex()}, tuple(backings + [worker.fileno()]))
        worker.close()
        until(lambda: rows() or ctl.exists(), 25)
        assert wire(ctl, "RESUME").startswith("ERR EBUSY") and not rows()

        def request(data):
            authority.sendall(data)
            return authority.recv(256)
        assert request(b"\3"+frame[8:64]).startswith(b"ERR")
        assert request(b"\1"+frame[:32]+secrets.token_bytes(32)+frame[64:]).startswith(b"ERR")
        if args.network:
            wrong=bytearray(frame)
            wrong[211]^=8
            assert request(b"\1"+wrong).startswith(b"ERR"), "wrong target TAP accepted"
        assert request(b"\1"+frame) == b"OK applying"
        expected = b"OK failed_held" if fail else b"OK identity_ready"
        def ready():
            phase = request(b"\2"+frame[8:64])
            if phase == b"OK failed_held" and not fail:
                raise RuntimeError(f"identity helper failed in {name}")
            return phase == expected
        until(ready)
        time.sleep(.25)
        assert not rows()
        if args.network:
            assert not ping(epoch), "closed Guest answered before activation"
        assert request(b"\3"+secrets.token_bytes(56)).startswith(b"ERR")
        if fail:
            assert request(b"\3"+frame[8:64]).startswith(b"ERR")
            authority.close()
            time.sleep(.2)
            assert not rows() and wire(ctl,"RESUME").startswith("ERR EBUSY")
            return
        assert request(b"\3"+frame[8:64]) == b"OK activating"
        until(lambda: len(rows()) >= 3)
        assert all(row[1:] == (pid,hostname,machine.hex().encode()) for row in rows()), rows()[:3]
        if args.network:
            until(lambda:ping(epoch))
            observed=(f"UPLINK {address(epoch)}2 "+mac(epoch).hex(":")+f" nameserver {address(epoch)}1").encode()
            assert observed in (directory/(name+".log")).read_bytes()
        assert request(b"\2"+frame[8:64]) == b"OK released"
        return ctl, rows, lambda: request(b"\1"+frame), machine.hex()

    try:
        control, source = launch("source", {})
        until(lambda: len(source()) >= 3, 40)
        pid = source()[-1][1]
        assert source()[-1][2:] == (b"capture-source", SOURCE_ID.encode())
        token, point = capture(control, 1, "capture")
        fixed = source()
        ctl, child, replay, identity = restored("child",point,2,"child-target")
        assert int(child()[0][0]) > int(fixed[-1][0]) and source() == fixed
        restored("invalid",point,3,"-invalid",fail=True)
        assert source() == fixed
        processes[-1].kill()
        processes[-1].wait()
        assert wire(control, f"STANDBY_WAKE {token}").startswith("OK")
        until(lambda: len(source()) > len(fixed)+2)
        assert source()[-1][1:] == (pid,b"capture-source",SOURCE_ID.encode())
        if args.network:
            until(lambda:ping(1))
            print("Guest packet gate stopped kernel ICMP throughout park and target identity; source and child have independent live uplinks",flush=True)
        print(f"parked source and child preserved PID {pid.decode()}; {len(point[2])} sealed RAM FDs; failed identity stayed quarantined",flush=True)
        child_token, branch = capture(ctl, 2, "recursive")
        parked = child()
        assert replay() == b"OK released"
        time.sleep(.2)
        assert child() == parked and '"source_disposition":"STANDBY"' in wire(ctl,f"STANDBY_QUERY {child_token}")
        assert set(json.loads(point[1])["backing_sizes"]) < set(json.loads(branch[1])["backing_sizes"])
        for ancestor in processes[:2]:
            ancestor.kill()
            ancestor.wait()
        for fd in point[2]:
            os.close(fd)
            handles.remove(fd)
        shutil.rmtree(point[0])
        _, grandchild, _, grand_id = restored("grandchild",branch,4,"grandchild")
        assert int(grandchild()[0][0]) > int(parked[-1][0]) and grand_id != identity
        print(f"grandchild resumed same PID after both ancestors exited, with {len(branch[2])} base and delta FDs",flush=True)
    finally:
        for authority in authorities:
            authority.close()
        for proc in processes:
            proc.kill()
            proc.wait()
        for fd in handles:
            os.close(fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lib", type=Path)
    parser.add_argument("--counter", type=Path)
    parser.add_argument("--helper", type=Path)
    parser.add_argument("--boot", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--network", action="store_true",help="isolated netns with CAP_NET_ADMIN and ping")
    args = parser.parse_args()
    args.lib = args.lib.resolve()
    if args.boot:
        boot(args, json.loads(args.boot.read_text()))
    else:
        with tempfile.TemporaryDirectory() as temp:
            run(args, args.work.resolve() if args.work else Path(temp))
