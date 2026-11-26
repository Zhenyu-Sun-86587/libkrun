// SPDX-License-Identifier: Apache-2.0
//! Disposable Worker smoke for the libkrun RAM backend on real KVM.
//! Runs the two-memory-slot probe and, with blk, the held libkrun VMM path.

#[cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "tee")))]
mod smoke {
    use krun_vmm::kernel_cow::{KernelCow, RamLayout};
    use kvm_bindings::{kvm_regs, kvm_userspace_memory_region};
    use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
    use std::io::{self, BufRead, Write};
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};
    use std::process::{Child, Command, Stdio};
    use vm_memory::{
        Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
    };

    const WRITER: GuestAddress = GuestAddress(0);
    const READER: GuestAddress = GuestAddress(0x100);
    const DATA: GuestAddress = GuestAddress(0x1000);
    const COLD: GuestAddress = GuestAddress(0x1001);

    fn layout() -> RamLayout {
        RamLayout::new(&[(WRITER, 4096), (DATA, 4096)]).unwrap()
    }

    fn vm(memory: &GuestMemoryMmap) -> (VmFd, VcpuFd) {
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        for (slot, region) in memory.iter().enumerate() {
            // SAFETY: the caller keeps the memory for the lifetime of this VM.
            // The two slots cover separate backing mappings.
            unsafe {
                vm.set_user_memory_region(kvm_userspace_memory_region {
                    slot: slot as u32,
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len(),
                    userspace_addr: memory.get_host_address(region.start_addr()).unwrap() as u64,
                    flags: 0,
                })
            }
            .unwrap();
        }
        let cpu = vm.create_vcpu(0).unwrap();
        let mut sregs = cpu.get_sregs().unwrap();
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        sregs.ds.base = 0;
        sregs.ds.selector = 0;
        cpu.set_sregs(&sregs).unwrap();
        (vm, cpu)
    }

    fn guest_run(cpu: &mut VcpuFd, entry: GuestAddress, address: GuestAddress, value: u8) -> u8 {
        cpu.set_regs(&kvm_regs {
            rip: entry.raw_value(),
            rflags: 2,
            rax: value as u64,
            rbx: address.raw_value(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
        cpu.get_regs().unwrap().rax as u8
    }

    fn reply(value: &str) {
        println!("{value}");
        io::stdout().flush().unwrap();
    }

    fn donor(kernel: &KernelCow) {
        let mem = kernel.allocate(&layout()).unwrap();
        // Real-mode mov [bx],al; hlt and mov al,[bx]; hlt.
        mem.write_slice(&[0x88, 0x07, 0xf4], WRITER).unwrap();
        mem.write_slice(&[0x8a, 0x07, 0xf4], READER).unwrap();
        let (_vm, mut cpu) = vm(&mem);
        guest_run(&mut cpu, WRITER, DATA, 0x31);
        guest_run(&mut cpu, WRITER, COLD, 0xa4);
        cpu.set_regs(&kvm_regs {
            rip: READER.raw_value(),
            rflags: 2,
            rbx: DATA.raw_value(),
            rcx: 0x4d21,
            ..Default::default()
        })
        .unwrap();
        let cut = cpu.get_regs().unwrap();
        reply(&format!(
            "held {} {} {} {}",
            cut.rip, cut.rflags, cut.rbx, cut.rcx
        ));
        let mut input = io::stdin().lock();
        for expected in ["write", "read", "exit"] {
            let mut command = String::new();
            input.read_line(&mut command).unwrap();
            assert_eq!(command.trim_end(), expected);
            match expected {
                "write" => {
                    guest_run(&mut cpu, WRITER, DATA, 0x42);
                    reply("held");
                }
                "read" => {
                    assert_eq!(guest_run(&mut cpu, READER, DATA, 0), 0x42);
                    reply("isolated");
                }
                _ => return,
            }
        }
    }

    struct Donor(Child);
    impl Drop for Donor {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn line(output: &mut impl BufRead, expected: &str) {
        let mut reply = String::new();
        output.read_line(&mut reply).unwrap();
        assert_eq!(reply.trim_end(), expected);
    }

    fn target(kernel: &KernelCow) {
        let mut donor = Donor(
            Command::new(std::env::current_exe().unwrap())
                .arg("--donor")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut input = donor.0.stdin.take().unwrap();
        let mut output = io::BufReader::new(donor.0.stdout.take().unwrap());
        let mut cut = String::new();
        output.read_line(&mut cut).unwrap();
        let [tag, rip, rflags, rbx, rcx] = cut
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(tag, "held");
        let checkpoint = kvm_regs {
            rip: rip.parse().unwrap(),
            rflags: rflags.parse().unwrap(),
            rbx: rbx.parse().unwrap(),
            rcx: rcx.parse().unwrap(),
            ..Default::default()
        };
        // SAFETY: pidfd_open takes numeric arguments. The direct child is live
        // and blocked waiting for subsequent fixture commands.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, donor.0.id(), 0) };
        assert!(fd >= 0, "{}", io::Error::last_os_error());
        // SAFETY: successful pidfd_open returned a new owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        // SAFETY: the donor is our controlled child at its verified held
        // boundary, with the exact same deterministic layout.
        let mem = unsafe { kernel.import_held(pidfd.as_fd(), &layout()) }.unwrap();
        drop(pidfd);
        let (_vm, mut cpu) = vm(mem.memory());
        writeln!(input, "write").unwrap();
        line(&mut output, "held");
        cpu.set_regs(&checkpoint).unwrap();
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
        let restored = cpu.get_regs().unwrap();
        assert_eq!(restored.rax as u8, 0x31);
        assert_eq!(restored.rcx, 0x4d21);
        guest_run(&mut cpu, WRITER, DATA, 0x53);
        writeln!(input, "read").unwrap();
        line(&mut output, "isolated");
        writeln!(input, "exit").unwrap();
        assert!(donor.0.wait().unwrap().success());
        // No target load or VMM memory read has touched this byte yet.
        assert_eq!(guest_run(&mut cpu, READER, COLD, 0), 0xa4);
        assert_eq!(guest_run(&mut cpu, READER, DATA, 0), 0x53);
        println!(
            "libkrun CoW KVM: fixed HVA, two memory slots, restored vCPU registers, 31/42/53 writes, cold a4 after donor exit"
        );
    }

    #[cfg(feature = "blk")]
    mod held_vmm {
        use super::*;
        use devices::virtio::guest_gate::TargetScope;
        use krun_vmm::Vmm;
        use krun_vmm::builder::{build_kernel_cow_source, build_kernel_cow_target};
        use krun_vmm::kernel_cow::{MAX_CHECKPOINT_BYTES, PreparedRam, import_for_worker};
        use krun_vmm::resources::VmResources;
        use krun_vmm::vmm_config::external_kernel::{ExternalKernel, KernelFormat};
        use polly::event_manager::EventManager;
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::os::unix::process::CommandExt;
        use std::path::{Path, PathBuf};
        use std::time::{Duration, Instant};

        const TOKEN: &str = "1 00000000000000000000000000000001";
        const MARKER: GuestAddress = GuestAddress(0x400000);
        const COMMAND: GuestAddress = GuestAddress(0x400002);
        const RESULT: GuestAddress = GuestAddress(0x400003);
        const REGISTER: GuestAddress = GuestAddress(0x400004);

        const GATE: GuestAddress = GuestAddress(0x400020);
        const ANCHOR: [u8; 16] = 2_u128.to_be_bytes();
        const HELPER: [u8; 32] = [0x43; 32];
        const TARGET: TargetScope = TargetScope {
            anchor: ANCHOR,
            epoch: 7,
            context: [0x69; 32],
        };
        const SOURCE_UID: u32 = 20101;
        const TARGET_UID: u32 = 20102;
        const KVM_GROUP: u32 = 20103;

        core::arch::global_asm!(include_str!("kernel_cow_guest.S"));

        unsafe extern "C" {
            static kernel_cow_guest_start: u8;
            static kernel_cow_guest_end: u8;
        }

        fn fixture_elf(path: &Path) {
            let start = &raw const kernel_cow_guest_start;
            let end = &raw const kernel_cow_guest_end;
            // SAFETY: these labels enclose one initialized read-only assembler section.
            let code = unsafe { std::slice::from_raw_parts(start, end.addr() - start.addr()) };
            let mut elf = vec![0_u8; 4096];
            elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            elf[16..20].copy_from_slice(&[2, 0, 62, 0]); // ET_EXEC, EM_X86_64
            elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
            elf[24..32].copy_from_slice(&0x20_0000_u64.to_le_bytes());
            elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
            elf[52..58].copy_from_slice(&[64, 0, 56, 0, 1, 0]);
            elf[64..72].copy_from_slice(&[1, 0, 0, 0, 5, 0, 0, 0]); // RX PT_LOAD
            for (field, value) in [
                4096,
                0x20_0000,
                0x20_0000,
                code.len() as u64,
                code.len() as u64,
                4096,
            ]
            .into_iter()
            .enumerate()
            {
                let offset = 72 + field * 8;
                elf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            elf.extend_from_slice(code);
            std::fs::write(path, elf).unwrap();
        }

        fn resources(path: PathBuf) -> VmResources {
            let mut resources = VmResources::default();
            resources.guest_gate = true;
            resources.guest_identity_helper = Some(HELPER);
            resources.set_external_kernel(ExternalKernel {
                path,
                format: KernelFormat::Elf,
                ..Default::default()
            });
            resources
        }

        fn until(memory: &GuestMemoryMmap, address: GuestAddress, expected: u8) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let actual = memory.read_obj::<u8>(address).unwrap();
                if actual == expected {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "GPA {address:?}: expected {expected:#x}, read {actual:#x}"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        fn guest_command(memory: &GuestMemoryMmap, command: u8) {
            memory.write_obj(command, COMMAND).unwrap();
            until(memory, COMMAND, 0);
        }

        fn wait_for_phase(mut observe: impl FnMut() -> String, phase: &str) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let actual = observe();
                if actual.split_ascii_whitespace().any(|word| word == phase) {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "expected {phase}, observed {actual}"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        fn park(source: &mut Vmm, memory: &GuestMemoryMmap) {
            let inventory = source.deep_virtio_inventory().unwrap();
            let inventory: serde_json::Value =
                serde_json::from_str(inventory.strip_prefix("OK ").unwrap()).unwrap();
            let gate = inventory["devices"]
                .as_array()
                .unwrap()
                .iter()
                .find(|device| device["device_id"] == "guest-gate")
                .unwrap();
            let address = gate["mmio_address"].as_u64().unwrap();
            assert!((0x40000000..0x1_00000000).contains(&address));
            memory.write_obj(address, GATE).unwrap();
            let prepare = format!("{TOKEN} 1000 10000");
            wait_for_phase(
                || {
                    source
                        .guest_gate_control("GUEST_GATE_PREPARE", &prepare)
                        .unwrap_or_else(str::to_owned)
                },
                "armed",
            );
            let park = format!("{TOKEN} {:032x}", u128::from_be_bytes(ANCHOR));
            source.guest_gate_control("GUEST_GATE_PARK", &park).unwrap();
            wait_for_phase(
                || {
                    source
                        .guest_gate_control("GUEST_GATE_QUERY", TOKEN)
                        .unwrap()
                },
                "parked",
            );
        }

        fn activate(child: &mut Vmm, memory: &GuestMemoryMmap) {
            let mut apply = [0_u8; 193];
            apply[..9].copy_from_slice(b"\x01SGI1\x01\0\0\0");
            apply[9..25].copy_from_slice(&3_u128.to_le_bytes());
            apply[25..33].copy_from_slice(&TARGET.epoch.to_le_bytes());
            apply[33..65].copy_from_slice(&TARGET.context);
            apply[65..97].fill(0x51);
            let mut status = [0_u8; 57];
            status[0] = 2;
            status[1..].copy_from_slice(&apply[9..65]);
            assert_eq!(child.target_identity_request(&apply).unwrap(), "applying");
            wait_for_phase(
                || child.target_identity_request(&status).unwrap().into(),
                "identity_ready",
            );
            assert_eq!(memory.read_obj::<u8>(COMMAND).unwrap(), 0x53);
            status[0] = 3;
            child.target_identity_request(&status).unwrap();
            status[0] = 2;
            wait_for_phase(
                || child.target_identity_request(&status).unwrap().into(),
                "released",
            );
        }

        pub(super) fn donor(kernel: KernelCow, path: PathBuf) {
            let mut events = EventManager::new().unwrap();
            let (sender, _receiver) = crossbeam_channel::unbounded();
            let source =
                build_kernel_cow_source(&resources(path), &mut events, None, sender, kernel)
                    .unwrap();
            let memory = source.lock().unwrap().guest_memory().clone();
            until(&memory, MARKER, 0x31);
            let mut source = source.lock().unwrap();
            park(&mut source, &memory);
            source.prepare_held_kernel_cow(TOKEN).unwrap();
            assert!(
                source
                    .held_capture_export(TOKEN)
                    .err()
                    .unwrap()
                    .contains("no native file export")
            );
            assert!(
                source
                    .held_capture_control("CAPTURE_FINISH", &format!("{TOKEN} CONTINUE"))
                    .is_err()
            );
            let mut output = io::stdout().lock();
            assert!(
                source
                    .held_kernel_cow_export("2 00000000000000000000000000000001")
                    .is_err()
            );
            source
                .held_kernel_cow_export(TOKEN)
                .unwrap()
                .write_to(&mut output)
                .unwrap();
            output.flush().unwrap();
            let mut input = io::stdin().lock();
            line(&mut input, "imported");
            source.confirm_held_kernel_cow_import(TOKEN).unwrap();
            source
                .held_capture_control("CAPTURE_FINISH", &format!("{TOKEN} CONTINUE"))
                .unwrap();
            assert!(source.held_kernel_cow_export(TOKEN).is_err());
            wait_for_phase(
                || {
                    source
                        .guest_gate_control("GUEST_GATE_QUERY", TOKEN)
                        .unwrap()
                },
                "released",
            );
            drop(source);
            guest_command(&memory, 0x42);
            until(&memory, MARKER, 0x42);
            writeln!(output, "resumed").unwrap();
            output.flush().unwrap();
            line(&mut input, "check");
            until(&memory, MARKER, 0x42);
            writeln!(output, "isolated").unwrap();
            output.flush().unwrap();
            line(&mut input, "exit");
            std::process::exit(0);
        }

        fn pidfd(pid: u32) -> OwnedFd {
            // SAFETY: pidfd_open takes scalar arguments and returns a new FD.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            assert!(fd >= 0, "{}", io::Error::last_os_error());
            // SAFETY: pidfd_open returned this new descriptor.
            unsafe { OwnedFd::from_raw_fd(fd as i32) }
        }

        pub(super) fn unauthorized_import(
            kernel: &KernelCow,
            source: u32,
            ranges: &[(GuestAddress, usize)],
        ) {
            let donor = pidfd(source);
            let layout = RamLayout::new(ranges).unwrap();
            // SAFETY: the fixture owns both processes and keeps the donor
            // held throughout. This subprocess has the target's ordinary UID.
            let result = unsafe { kernel.import_held(donor.as_fd(), &layout) };
            let error = result
                .err()
                .expect("ordinary target UID imported cross-UID RAM");
            assert!(
                matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)),
                "{error}"
            );
        }

        fn assert_worker_drop(raw_fd: i32) {
            // SAFETY: scalar identity/fd queries and an attempt to regain UID 0,
            // which must fail for the now unprivileged target.
            unsafe {
                assert_eq!(libc::fcntl(raw_fd, libc::F_GETFD), -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
                assert_eq!(libc::geteuid(), TARGET_UID);
                assert_eq!(libc::getegid(), TARGET_UID);
                assert_eq!(libc::setuid(0), -1);
                assert_eq!(libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), 1);
            }
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            for key in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
                assert!(
                    status.lines().any(|line| line.split_once(':').is_some_and(
                        |(field, value)| field == key && value.trim() == "0000000000000000"
                    )),
                    "{key} wasn't cleared"
                );
            }
        }

        pub(super) fn failed_worker_import() {
            let bad: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
            let raw_fd = bad.as_raw_fd();
            // SAFETY: this disposable bootstrap deliberately passes a
            // non-pidfd. The kernel rejects it before examining any source.
            let result = unsafe {
                import_for_worker(bad, &layout(), TARGET_UID, TARGET_UID, Some(KVM_GROUP))
            };
            assert!(result.is_err());
            assert_worker_drop(raw_fd);
        }

        fn deny_cow_in_guest_runtime() {
            KernelCow::probe().expect("unfiltered CoW probe");
            let marker = std::fs::read_to_string("/sys/kernel/smolvm_cow/abi").unwrap();
            let nr = marker
                .lines()
                .find_map(|line| line.strip_prefix("syscall_nr="))
                .unwrap()
                .parse::<u32>()
                .unwrap();
            let op = |code: u16, jump_on_false: u8, arg: u32| libc::sock_filter {
                code,
                jt: 0,
                jf: jump_on_false,
                k: arg,
            };
            // Test filter for this known x86_64 lab process. It leaves KVM
            // available but rejects any query or import after the credential drop.
            let mut instructions = [
                op((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0, 0),
                op((libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16, 1, nr),
                op(
                    (libc::BPF_RET | libc::BPF_K) as u16,
                    0,
                    libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                ),
                op(
                    (libc::BPF_RET | libc::BPF_K) as u16,
                    0,
                    libc::SECCOMP_RET_ALLOW,
                ),
            ];
            let program = libc::sock_fprog {
                len: instructions.len() as u16,
                filter: instructions.as_mut_ptr(),
            };
            // SAFETY: the kernel copies the bounded classic BPF program.
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        &raw const program,
                    )
                },
                0
            );
            let rejected = KernelCow::probe()
                .err()
                .expect("seccomp allowed the private CoW syscall");
            assert_eq!(rejected.raw_os_error(), Some(libc::EPERM));
        }

        fn worker_import(
            source: u32,
            donor: OwnedFd,
            ranges: &[(GuestAddress, usize)],
        ) -> PreparedRam {
            let exe = std::env::current_exe().unwrap();
            assert!(
                Command::new(&exe)
                    .arg("--bootstrap-failure")
                    .status()
                    .unwrap()
                    .success()
            );
            // The first import targets the real donor layout without privileges.
            let mut reject = Command::new(exe);
            reject.arg("--import-denied").arg(source.to_string());
            for (guest, size) in ranges {
                reject
                    .arg(guest.raw_value().to_string())
                    .arg(size.to_string());
            }
            assert!(
                reject
                    .uid(TARGET_UID)
                    .gid(TARGET_UID)
                    .status()
                    .unwrap()
                    .success()
            );

            let layout = RamLayout::new(ranges).unwrap();
            let raw_fd = donor.as_raw_fd();
            // SAFETY: exact source is the held, fixture-owned donor. This is the
            // single-threaded final target before it opens its own KVM handle.
            let memory = unsafe {
                import_for_worker(donor, &layout, TARGET_UID, TARGET_UID, Some(KVM_GROUP))
            }
            .unwrap();
            assert_worker_drop(raw_fd);
            deny_cow_in_guest_runtime();
            println!(
                "libkrun Worker CoW: UID {TARGET_UID} denied for UID {SOURCE_UID}, bootstrap succeeded, failure drops privileges, pidfds closed, capabilities cleared, post-drop syscall denied"
            );
            memory
        }

        pub(super) fn target(kernel: &KernelCow, cross_uid: bool) {
            if cross_uid {
                let kvm = std::fs::metadata("/dev/kvm").unwrap();
                assert_eq!(kvm.gid(), KVM_GROUP, "use the dedicated nested KVM fixture");
                assert_eq!(kvm.mode() & 0o777, 0o660);
            }
            let fixture = tempfile::tempdir().unwrap();
            if cross_uid {
                std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            let path = fixture.path().join("guest.elf");
            fixture_elf(&path);
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .arg("--vmm-donor")
                .arg(&path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped());
            if cross_uid {
                command.uid(SOURCE_UID).gid(KVM_GROUP);
            }
            let mut source = Donor(command.spawn().unwrap());
            let mut input = source.0.stdin.take().unwrap();
            let mut output = io::BufReader::new(source.0.stdout.take().unwrap());
            let mut header = String::new();
            output.read_line(&mut header).unwrap();
            let header: serde_json::Value =
                serde_json::from_str(header.strip_prefix("OK ").unwrap()).unwrap();
            assert_eq!(header["protocol"], "KernelCowHeld/1");
            assert_eq!(header["session"], 1);
            assert_eq!(header["hold_token"], TOKEN.split_once(' ').unwrap().1);
            let length = header["checkpoint_bytes"].as_u64().unwrap() as usize;
            assert!((1..=MAX_CHECKPOINT_BYTES).contains(&length));
            let ranges = header["regions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|region| {
                    (
                        GuestAddress(region["guest_start"].as_u64().unwrap()),
                        region["size"].as_u64().unwrap() as usize,
                    )
                })
                .collect::<Vec<_>>();
            let mut checkpoint = vec![0; length];
            output.read_exact(&mut checkpoint).unwrap();
            fixture.close().unwrap();
            let source_pid = source.0.id();
            let donor = pidfd(source_pid);
            let memory = if cross_uid {
                worker_import(source_pid, donor, &ranges)
            } else {
                let layout = RamLayout::new(&ranges).unwrap();
                // SAFETY: the libkrun actor is held and all writers have been quiesced.
                unsafe { kernel.import_held(donor.as_fd(), &layout) }.unwrap()
            };
            writeln!(input, "imported").unwrap();
            line(&mut output, "resumed");
            let mut events = EventManager::new().unwrap();
            let (sender, _receiver) = crossbeam_channel::unbounded();
            let mut config = resources(path);
            config.guest_target = Some(TARGET);
            let child =
                build_kernel_cow_target(&config, &mut events, None, sender, memory, checkpoint)
                    .unwrap();
            let memory = child.lock().unwrap().guest_memory().clone();
            until(&memory, MARKER, 0x31);
            memory.write_obj(0x53_u8, COMMAND).unwrap();
            activate(&mut child.lock().unwrap(), &memory);
            until(&memory, MARKER, 0x53);
            writeln!(input, "check").unwrap();
            line(&mut output, "isolated");
            writeln!(input, "exit").unwrap();
            assert!(source.0.wait().unwrap().success());
            guest_command(&memory, 0xff);
            until(&memory, RESULT, 0xa4);
            assert_eq!(memory.read_obj::<u32>(REGISTER).unwrap(), 0x4d21);
            until(&memory, MARKER, 0x53);
            child.lock().unwrap().pause().unwrap();
            println!(
                "libkrun held CoW VMM: real KVM builder resume, Guest gate quarantine and activation, no native file export, guest writes isolated, cold page after source exit"
            );
        }
    }

    pub fn main() {
        let kernel = match KernelCow::probe() {
            Ok(kernel) => kernel,
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                eprintln!("{error}");
                std::process::exit(4);
            }
            Err(error) => panic!("CoW discovery failed: {error}"),
        };
        match std::env::args().nth(1).as_deref() {
            Some("--donor") => donor(&kernel),
            #[cfg(feature = "blk")]
            Some("--vmm-donor") => {
                held_vmm::donor(kernel, std::env::args_os().nth(2).unwrap().into())
            }
            #[cfg(feature = "blk")]
            Some("--import-denied") => {
                let mut args = std::env::args().skip(2);
                let pid = args.next().unwrap().parse().unwrap();
                let mut ranges = Vec::new();
                while let Some(guest) = args.next() {
                    ranges.push((
                        GuestAddress(guest.parse().unwrap()),
                        args.next().unwrap().parse().unwrap(),
                    ));
                }
                held_vmm::unauthorized_import(&kernel, pid, &ranges);
            }
            #[cfg(feature = "blk")]
            Some("--cross-uid") => {
                target(&kernel);
                held_vmm::target(&kernel, true);
            }
            #[cfg(feature = "blk")]
            Some("--bootstrap-failure") => held_vmm::failed_worker_import(),
            _ => {
                target(&kernel);
                #[cfg(feature = "blk")]
                held_vmm::target(&kernel, false);
            }
        }
    }
}

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "tee")))]
    smoke::main();
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", not(feature = "tee"))))]
    std::process::exit(4);
}
