# Host-controlled source Guest freeze on Linux x86-64

Build libkrun with its normal Linux Makefile and a static init. Build libkrunfw
with the matching host-freezer patch and the `host-freezer-x86_64.config`
fragment. The device is added only when the caller explicitly invokes
`krun_enable_guest_gate_v1` before launch. The VMM's private control socket
accepts these operations.

| Operation | Arguments | Successful result |
| --- | --- | --- |
| GUEST_GATE_PREPARE | session number, fresh 32-hex-digit nonce, freeze timeout (100–3000 ms), hold timeout (100–60000 ms) | Preparing until the kernel confirms all ordinary userspace is frozen |
| GUEST_GATE_QUERY | session number, nonce | The current phase and signed kernel error |
| GUEST_GATE_RELEASE | session number, nonce | Releasing until the Guest confirms thaw |
| GUEST_GATE_ABORT | session number, nonce | Aborting until the Guest confirms thaw |

Session numbers increase within one VMM. Repeating a command with the same
parameters returns the current phase. A lost client reconnects and queries the
same session. The Guest kernel bounds a source hold on its own clock. Queries
retain uncertainty after an active device reset. This source-freeze transport
rejects capture until the target-side rebind and activation contract is present.

Run the test in an isolated KVM worker with a matching firmware on the dynamic
loader path. The fixture boots three counter processes on two vCPUs, including
a child PID namespace. The host samples their synced counters while armed,
then observes all three advance after each source thaw.

```sh
cc -static -O2 -Wall -Wextra -Werror tests/guest_gate/counters.c -o /tmp/gate-counters
LD_LIBRARY_PATH="$FIRMWARE_DIR" python3 tests/guest_gate/probe.py "$LIBKRUN_SO" /tmp/gate-counters
```

The `--standby` option attaches a writable disk and a read-only disk. It checks
`CAPTURE_INVENTORY` against their names, capacities and access modes, and
uses `STANDBY_ENTER <session> <nonce> raw`, `STANDBY_QUERY` and
`STANDBY_WAKE`. The enter response records `clone_ready=false`. This path
holds the vCPUs and drains the device workers in the current VMM. Device drain
failure leaves it held. A stale token and an unscoped legacy RESUME are both
rejected. On a two-second hold, all three Guest counters and a raw disk
counter remained fixed, then advanced after wake. The test also checks that
the Guest monotonic clock excludes the pause.

Use `--capture` to exercise the native raw capture control socket. A nonzero
session number and a random 128-bit token identify one transaction. Prepare
pauses the vCPUs, drains devices, records CPU, VM and device state, and seals
the source RAM in place. A subsequent capture retains the base files and
records private dirty pages as immutable delta files. The raw receipt has
`clone_ready=false` because mutable disk and external attachments are visible
in its inventory and require separate resource authority.

The prepare command takes `<session> <token> raw`. Query, export and cancel
take the same session and token. Finish additionally accepts `KEEP_HELD` or
`CONTINUE`. A partially transferred export can be retried. The success line
declares the lengths of the binary checkpoint and JSON RAM descriptor, followed
by those two payloads and one SCM_RIGHTS message per sorted backing ID.
The test closes a connection during transfer, compares repeated exports down
to their inode numbers and seals, and checks that a cancelled capture can no
longer be exported. An incomplete remap or capture remains held for diagnosis.

### Parked identity restore

For a managed standby, first prepare the measured freezer and wait for
`armed`. Supply a separate random 128-bit capture anchor with
`GUEST_GATE_PARK <session> <nonce> <anchor>` and wait for `parked` before
`STANDBY_ENTER <session> <nonce> managed`. The Guest stays frozen across
the preparation deadline. A wake becomes RUNNING after the Guest confirms
thaw. A parked capture from standby accepts RETURN_STANDBY without advancing
the source. Its descriptor and checkpoint can be exported through the same
held-capture socket used for raw observation.

The restricted target profile supports a Worker-provisioned read-only block
generation, the measured virtual-only init used to pivot to that root,
console, balloon and RNG. It validates the actual registered devices and the
block closure while vCPUs are paused. Linux x86_64 targets bind the captured
anchor, the helper digest and a fresh execution context to a dedicated
AF_UNIX SOCK_SEQPACKET socket supplied by the host. The normal VMM control
socket cannot start identity or authorize activation.

Each private request occupies one packet. Byte 1 as an opcode is followed by
the 192-byte SGI1 request, including challenge, epoch, execution context
digest, fresh entropy, machine ID and hostname. Opcodes 2 and 3 query and
commit activation, each followed by bytes 8 through 63 of the same request.
The host observes `identity_ready` before committing. A failed helper remains
`failed_held` after the authority disconnects. Completed authority replays
cannot wake a later standby. A broader storage or network profile needs its
own writer and attachment decisions.

Run the following on an isolated KVM Worker with the matching firmware, the
statically compiled helper and mke2fs. The probe verifies source/child
identity separation, quarantine on failure, preservation of the original
user process, and restoration of a grandchild after both ancestor VMMs exit.

```sh
cc -static -O2 -Wall -Wextra -Werror tests/guest_gate/identity_counter.c -o /tmp/identity-counter
LD_LIBRARY_PATH="$FIRMWARE_DIR" python3 tests/guest_gate/target_probe.py "$LIBKRUN_SO" \
    --counter /tmp/identity-counter --helper "$MEASURED_HELPER"
```

### Managed IPv4 packet gate

A source with one Worker-managed TapFd must park with `GUEST_GATE_PARK_NETWORK`.
The kernel returns the parked acknowledgement after closing packet ingress and
egress across Guest network namespaces. A target restores the same stable
virtio-net profile on a fresh attachment. It requires the source and target
MAC in the SGI2 identity request to match the registered TAPs. A network-free
target continues to use SGI1.

Pass `--network` to the target probe in a private network namespace with
CAP_NET_ADMIN, iproute2 and ping. Each host TAP intentionally stays up. The
source kernel answers ICMP after userspace freezes and stops answering after
network park. A target stays silent while applying its identity and answers
at the new IP after the private activation decision. The fixture reads the
new MAC, IPv4 address and DNS file from the resumed userspace process and
repeats the restore across a second generation. Host-side routing, writer
receipts and the Worker activation journal have separate integration tests.

The private BEGIN packet uses opcode 1 followed by a 256-byte frame. The first
eight bytes are `SGI2` and little-endian version 2. Bytes 8 through 191
have the SGI1 layout. The extension has these half-open byte offsets.

| Offset | Field |
| --- | --- |
| 192..196 | NET1 |
| 196..200 | mode (1 native or 2 fixed), old prefix length, new prefix length, reserved zero |
| 200..212 | old and new six-byte unicast MACs |
| 212..232 | old IP, new IP, old gateway, new gateway, DNS server, each IPv4 in network byte order |
| 232..248 | NUL-terminated interface name, zero padded |
| 248..256 | reserved zero |

Both the source and new attachment, kernel/helper profile, execution epoch
and operation belong to the Worker context digest. A partial Guest update
keeps the target held. Network configuration uses NETLINK_ROUTE and touches
the selected Guest interface. The authority query/release binding continues
to use the 56 bytes starting at offset 8.
