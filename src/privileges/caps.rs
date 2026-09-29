//! Linux capabilities around the account switch: none survive it but `CAP_NET_RAW`, and that only
//! where this kernel needs it to pin DIAL connections to their interface.
//!
//! `SO_BINDTODEVICE` needs `CAP_NET_RAW` before Linux 5.7 (c427bfec18f2). Vendors backport, so the
//! switch tries the pin rather than reading the kernel version.
//!
//! Capabilities and `PR_SET_KEEPCAPS` are per thread: the daemon's whole process, since it is
//! single-threaded, but a test has to switch in a child process.

use std::io;
use std::os::fd::AsRawFd;

use super::{DialPin, PrivilegeError};
use crate::interface::InterfaceName;

const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_NET_RAW: u32 = 13;

/// A set of capabilities, bit `n` for capability `n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CapSet(u64);

impl CapSet {
    const EMPTY: Self = Self(0);

    const fn of(capability: u32) -> Self {
        Self(1 << capability)
    }

    const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn within(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// A thread's three capability sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sets {
    effective: CapSet,
    permitted: CapSet,
    inheritable: CapSet,
}

impl Sets {
    /// `set` both permitted and in effect, nothing inheritable.
    const fn only(set: CapSet) -> Self {
        Self {
            effective: set,
            permitted: set,
            inheritable: CapSet::EMPTY,
        }
    }
}

/// `_LINUX_CAPABILITY_VERSION_3`, for [`Header::version`].
const VERSION_3: u32 = 0x2008_0522;

/// `struct __user_cap_header_struct`.
#[repr(C)]
struct Header {
    version: u32,
    pid: libc::c_int,
}

/// `struct __user_cap_data_struct`; version 3 takes two, the low 32 capabilities first.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// What pinning a socket with no capability in effect showed.
#[derive(Debug)]
enum Pin {
    /// The pin works without `CAP_NET_RAW`: Linux 5.7 or later, or a backport.
    Unprivileged,
    /// The kernel refused it (`EPERM`): DIAL needs `CAP_NET_RAW` here.
    NeedsNetRaw,
    /// The probe itself failed; the answer is unknown.
    Unknown(io::Error),
}

/// While still root: keep only `CAP_SETUID` and `CAP_SETGID` for the switch ([`settle`] drops
/// them), plus `CAP_NET_RAW` when DIAL may need it, and carry them across the uid change.
///
/// # Errors
/// [`PrivilegeError::Withheld`] if the process lacks `CAP_SETUID` or `CAP_SETGID`, or
/// [`PrivilegeError::Drop`] naming the call that failed.
pub(super) fn narrow_for_switch(dial: bool) -> Result<(), PrivilegeError> {
    let held = get()?.permitted;
    for (capability, name) in [(CAP_SETUID, "CAP_SETUID"), (CAP_SETGID, "CAP_SETGID")] {
        if !held.contains(CapSet::of(capability)) {
            return Err(PrivilegeError::Withheld(name));
        }
    }
    let mut wanted = CapSet::of(CAP_SETUID).with(CapSet::of(CAP_SETGID));
    if dial {
        wanted = wanted.with(CapSet::of(CAP_NET_RAW));
    }
    set(Sets::only(wanted.within(held)))?;
    prctl("prctl(PR_SET_KEEPCAPS)", libc::PR_SET_KEEPCAPS, 1)
}

/// After the switch: probe the pin with nothing in effect, keep `CAP_NET_RAW` alone if the pin
/// needs it and it is held, else nothing, and check the sets.
///
/// # Errors
/// [`PrivilegeError::Drop`] naming the call that failed, or
/// [`PrivilegeError::CapabilitiesSurvived`] if the sets read back other than chosen.
pub(super) fn settle(dial: Option<&InterfaceName>) -> Result<DialPin, PrivilegeError> {
    let held = get()?.permitted;
    // Nothing in effect, so the probe's pin succeeds only if it needs no capability.
    set(Sets {
        effective: CapSet::EMPTY,
        permitted: held,
        inheritable: CapSet::EMPTY,
    })?;
    let pin = dial.map(probe);
    let decision = decide(pin.as_ref(), held);
    if let Some(Pin::Unknown(e)) = &pin {
        log::warn!(
            "cannot tell whether DIAL's interface pin needs CAP_NET_RAW on this kernel ({e}); \
             treating it as needed"
        );
    }
    if decision == DialPin::NotHeld {
        log::warn!(
            "DIAL's interface pin needs CAP_NET_RAW here and the process does not hold it: DIAL \
             connections will fail"
        );
    }
    let keep = if decision == DialPin::KeptNetRaw {
        CapSet::of(CAP_NET_RAW)
    } else {
        CapSet::EMPTY
    };
    set(Sets::only(keep))?;
    prctl("prctl(PR_SET_KEEPCAPS)", libc::PR_SET_KEEPCAPS, 0)?;
    if get()? != Sets::only(keep) {
        return Err(PrivilegeError::CapabilitiesSurvived);
    }
    Ok(decision)
}

/// Keep `CAP_NET_RAW` where the pin needs it or that could not be told, and only if `held`.
fn decide(pin: Option<&Pin>, held: CapSet) -> DialPin {
    match pin {
        None => DialPin::NoDial,
        Some(Pin::Unprivileged) => DialPin::Unprivileged,
        Some(Pin::NeedsNetRaw | Pin::Unknown(_)) if held.contains(CapSet::of(CAP_NET_RAW)) => {
            DialPin::KeptNetRaw
        }
        Some(Pin::NeedsNetRaw | Pin::Unknown(_)) => DialPin::NotHeld,
    }
}

/// Pin a fresh, unconnected TCP socket to `iface` the way DIAL pins each connection.
fn probe(iface: &InterfaceName) -> Pin {
    let socket = match crate::sys::blocking_socket(libc::AF_INET, libc::SOCK_STREAM, 0) {
        Ok(socket) => socket,
        Err(e) => return Pin::Unknown(e),
    };
    match crate::sys::setsockopt_bytes(
        socket.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_BINDTODEVICE,
        iface.as_bytes(),
    ) {
        Ok(()) => Pin::Unprivileged,
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => Pin::NeedsNetRaw,
        Err(e) => Pin::Unknown(e),
    }
}

/// This thread's capability sets.
fn get() -> Result<Sets, PrivilegeError> {
    let mut header = Header {
        version: VERSION_3,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // SAFETY: capget reads the header and writes the two version-3 data structs `data` holds.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) };
    if rc != 0 {
        return Err(failed("capget", io::Error::last_os_error()));
    }
    let join = |low: u32, high: u32| CapSet(u64::from(high) << 32 | u64::from(low));
    Ok(Sets {
        effective: join(data[0].effective, data[1].effective),
        permitted: join(data[0].permitted, data[1].permitted),
        inheritable: join(data[0].inheritable, data[1].inheritable),
    })
}

/// Set this thread's capability sets.
fn set(sets: Sets) -> Result<(), PrivilegeError> {
    let mut header = Header {
        version: VERSION_3,
        pid: 0,
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "splitting a 64-bit mask in halves"
    )]
    let half = |set: CapSet, shift: u32| (set.0 >> shift) as u32;
    let data = [0, 32].map(|shift| Data {
        effective: half(sets.effective, shift),
        permitted: half(sets.permitted, shift),
        inheritable: half(sets.inheritable, shift),
    });
    // SAFETY: capset reads the header and the two version-3 data structs `data` holds.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) };
    if rc != 0 {
        return Err(failed("capset", io::Error::last_os_error()));
    }
    Ok(())
}

fn prctl(
    step: &'static str,
    option: libc::c_int,
    value: libc::c_ulong,
) -> Result<(), PrivilegeError> {
    let zero: libc::c_ulong = 0;
    // SAFETY: a prctl option that takes one integer argument.
    crate::sys::check(unsafe { libc::prctl(option, value, zero, zero, zero) })
        .map_err(|source| failed(step, source))
}

fn failed(step: &'static str, source: io::Error) -> PrivilegeError {
    PrivilegeError::Drop { step, source }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt;

    use super::*;
    use crate::privileges::tests::{CHILD_MODE, TARGET, run_in_children};
    use crate::privileges::{Outcome, Switch, drop_to};

    #[test]
    fn cap_net_raw_is_kept_only_where_the_pin_needs_it_and_it_is_held() {
        let held = CapSet::of(CAP_NET_RAW).with(CapSet::of(CAP_SETUID));
        assert_eq!(decide(None, held), DialPin::NoDial);
        assert_eq!(
            decide(Some(&Pin::Unprivileged), held),
            DialPin::Unprivileged
        );
        assert_eq!(decide(Some(&Pin::NeedsNetRaw), held), DialPin::KeptNetRaw);
        // An unknown answer keeps DIAL working.
        let unknown = Pin::Unknown(io::Error::from_raw_os_error(libc::ENODEV));
        assert_eq!(decide(Some(&unknown), held), DialPin::KeptNetRaw);
        // Nothing is kept that was not held, and that is reported, not hidden.
        assert_eq!(
            decide(Some(&Pin::NeedsNetRaw), CapSet::EMPTY),
            DialPin::NotHeld
        );
        assert_eq!(decide(Some(&unknown), CapSet::EMPTY), DialPin::NotHeld);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "switches account and capabilities through raw syscalls"
    )]
    fn the_switch_keeps_cap_net_raw_only_where_the_pin_needs_it() {
        if let Ok(mode) = std::env::var(CHILD_MODE) {
            drop_in_child(&mode);
            return;
        }
        run_in_children(
            "privileges::caps::tests::the_switch_keeps_cap_net_raw_only_where_the_pin_needs_it",
            &["full", "keep", "denied"],
            |mode, command| {
                if mode != "denied" {
                    return;
                }
                // A runtime that withholds CAP_SETUID withholds it from every thread: out of the
                // bounding set before exec, root's child never holds it. (Taking it from one
                // thread instead makes the threads' setuid disagree, which glibc aborts on.)
                // SAFETY: the closure makes one async-signal-safe call between fork and exec.
                unsafe {
                    command.pre_exec(|| {
                        let (cap, zero) = (libc::c_ulong::from(CAP_SETUID), 0);
                        if libc::prctl(libc::PR_CAPBSET_DROP, cap, zero, zero, zero) == 0 {
                            Ok(())
                        } else {
                            Err(io::Error::last_os_error())
                        }
                    });
                }
            },
        );
    }

    /// A drop with DIAL on the loopback interface. `keep` fakes a kernel that refuses an
    /// unprivileged pin; `denied` runs without `CAP_SETUID`.
    fn drop_in_child(mode: &str) {
        match mode {
            "full" | "denied" => {}
            "keep" => refuse_unprivileged_pins(),
            _ => panic!("unknown {CHILD_MODE} {mode}"),
        }
        let outcome = drop_to(TARGET, Some(&InterfaceName::loopback()));
        if mode == "denied" {
            assert!(
                matches!(outcome, Err(PrivilegeError::Withheld("CAP_SETUID"))),
                "{outcome:?}"
            );
            return;
        }
        let keep = mode == "keep";
        assert_eq!(
            outcome.unwrap(),
            Outcome {
                switch: Switch::Dropped,
                dial_pin: if keep {
                    DialPin::KeptNetRaw
                } else {
                    DialPin::Unprivileged
                },
            }
        );
        let expected = if keep {
            CapSet::of(CAP_NET_RAW)
        } else {
            CapSet::EMPTY
        };
        assert_eq!(get().unwrap(), Sets::only(expected));
        let zero: libc::c_ulong = 0;
        // SAFETY: a plain prctl query.
        let keepcaps = unsafe { libc::prctl(libc::PR_GET_KEEPCAPS, zero, zero, zero, zero) };
        assert_eq!(keepcaps, 0);
    }

    /// From here on this thread's `SO_BINDTODEVICE` fails with `EPERM`, as before Linux 5.7 without
    /// `CAP_NET_RAW` in effect. Seccomp can't see capabilities, so it refuses even with one; the
    /// sets show what was kept.
    fn refuse_unprivileged_pins() {
        use libc::{
            BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, c_ulong, sock_filter,
            sock_fprog,
        };

        // `struct seccomp_data`: `nr` at 0, `args[n]` at 16 + 8n, its low word 4 bytes in on a
        // big-endian target.
        const NR: u32 = 0;
        const LOW: u32 = if cfg!(target_endian = "big") { 4 } else { 0 };
        const LEVEL: u32 = 24 + LOW;
        const OPTION: u32 = 32 + LOW;
        let op = |code: u32, k: u32, jt: u8, jf: u8| sock_filter {
            code: u16::try_from(code).unwrap(),
            jt,
            jf,
            k,
        };
        let mut filter = [
            op(BPF_LD | BPF_W | BPF_ABS, NR, 0, 0),
            op(
                BPF_JMP | BPF_JEQ | BPF_K,
                u32::try_from(libc::SYS_setsockopt).unwrap(),
                0,
                5,
            ),
            op(BPF_LD | BPF_W | BPF_ABS, LEVEL, 0, 0),
            op(
                BPF_JMP | BPF_JEQ | BPF_K,
                u32::try_from(libc::SOL_SOCKET).unwrap(),
                0,
                3,
            ),
            op(BPF_LD | BPF_W | BPF_ABS, OPTION, 0, 0),
            op(
                BPF_JMP | BPF_JEQ | BPF_K,
                u32::try_from(libc::SO_BINDTODEVICE).unwrap(),
                0,
                1,
            ),
            op(
                BPF_RET | BPF_K,
                libc::SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap(),
                0,
                0,
            ),
            op(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
        ];
        let prog = sock_fprog {
            len: u16::try_from(filter.len()).unwrap(),
            filter: filter.as_mut_ptr(),
        };
        let (one, zero): (c_ulong, c_ulong) = (1, 0);
        // SAFETY: plain prctl calls; the kernel copies `prog` before returning.
        unsafe {
            assert_eq!(
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero),
                0
            );
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    c_ulong::from(libc::SECCOMP_MODE_FILTER),
                    &raw const prog,
                ),
                0,
                "install the seccomp filter: {}",
                io::Error::last_os_error()
            );
        }
    }
}
