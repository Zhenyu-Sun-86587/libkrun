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
