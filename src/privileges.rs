//! Dropping root once the captures are open (the `user` setting). On Linux, `caps` also settles
//! the capabilities.

#[cfg(target_os = "linux")]
mod caps;

use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::ptr;

use libc::{c_char, c_int, gid_t, uid_t};
use thiserror::Error;

use crate::config::{Principal, RunAs};
use crate::interface::InterfaceName;
use crate::sys::check;

/// A numeric identity: the one to switch to, or an account's uid and primary group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Credentials {
    pub(crate) uid: uid_t,
    pub(crate) gid: gid_t,
}

#[derive(Debug, Error)]
pub(crate) enum PrivilegeError {
    #[error("no user named \"{0}\"")]
    UnknownUser(String),
    #[error("no group named \"{0}\"")]
    UnknownGroup(String),
    #[error("uid {0} has no account to take its group from; name the group as USER:GROUP")]
    NoPrimaryGroup(u32),
    #[error("the account must be unprivileged, not uid 0 or gid 0")]
    Privileged,
    #[error("started as uid {0}, not root, so it cannot switch to another account")]
    NotRoot(u32),
    #[error("cannot look up the account: {0}")]
    Lookup(io::Error),
    #[error("{step} failed: {source}")]
    Drop {
        step: &'static str,
        source: io::Error,
    },
    #[error("root privileges survived the switch; refusing to run")]
    StillPrivileged,
    #[cfg(any(target_os = "freebsd", target_os = "linux"))]
    #[error("no_new_privs did not take; refusing to run")]
    NewPrivilegesAllowed,
    #[cfg(target_os = "linux")]
    #[error("capabilities beyond the chosen ones survived the switch; refusing to run")]
    CapabilitiesSurvived,
    #[cfg(target_os = "linux")]
    #[error(
        "the process does not hold {0}, which the switch needs; a container runtime may withhold it"
    )]
    Withheld(&'static str),
}

/// How the process came to run as the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Switch {
    /// Started as root.
    Dropped,
    /// Started as the account already.
    AlreadyThatAccount,
}

impl Switch {
    /// How the startup line begins.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Dropped => "dropped root: running",
            Self::AlreadyThatAccount => "already running",
        }
    }
}

/// What the switch decided about DIAL's interface pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialPin {
    /// No DIAL entry, or a platform whose pin needs no capability.
    NoDial,
    /// This kernel pins without `CAP_NET_RAW`.
    #[cfg(target_os = "linux")]
    Unprivileged,
    /// `CAP_NET_RAW` kept: the pin needs it, or that could not be told.
    #[cfg(target_os = "linux")]
    KeptNetRaw,
    /// The pin needs `CAP_NET_RAW` and the process lacks it, so DIAL connections fail.
    #[cfg(target_os = "linux")]
    NotHeld,
}

impl DialPin {
    /// How the startup line ends: what the switch kept, and why.
    pub(crate) fn describe(self) -> &'static str {
        #[cfg(target_os = "linux")]
        match self {
            Self::KeptNetRaw => {
                ", keeping only CAP_NET_RAW, to pin DIAL connections to their interface"
            }
            Self::Unprivileged => {
                ", with no capabilities: this kernel pins DIAL connections to their interface \
                 without CAP_NET_RAW"
            }
            Self::NotHeld | Self::NoDial => ", with no capabilities",
        }

        #[cfg(not(target_os = "linux"))]
        match self {
            Self::NoDial => "",
        }
    }
}

/// What [`drop_to`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) switch: Switch,
    pub(crate) dial_pin: DialPin,
}

/// The numeric identity `run_as` names. A named user brings its primary group unless the setting
/// names one; a bare uid takes the group of the account behind it.
///
/// # Errors
/// [`PrivilegeError`] for an unknown account, or one that is root.
pub(crate) fn resolve(run_as: &RunAs) -> Result<Credentials, PrivilegeError> {
    // Numbers skip the account database, so they work where there is none.
    let (uid, primary) = match run_as.user() {
        Principal::Id(uid) => (*uid, None),
        Principal::Name(name) => {
            let account =
                user_by_name(name)?.ok_or_else(|| PrivilegeError::UnknownUser(name.clone()))?;
            (account.uid, Some(account.gid))
        }
    };
    let gid = match (run_as.group(), primary) {
        (Some(Principal::Id(gid)), _) => *gid,
        (Some(Principal::Name(name)), _) => {
            group_by_name(name)?.ok_or_else(|| PrivilegeError::UnknownGroup(name.clone()))?
        }
        (None, Some(gid)) => gid,
        (None, None) => user_by_id(uid)?
            .map(|account| account.gid)
            .ok_or(PrivilegeError::NoPrimaryGroup(uid))?,
    };
    if uid == 0 || gid == 0 {
        return Err(PrivilegeError::Privileged);
    }
    Ok(Credentials { uid, gid })
}

/// Run as `credentials` from here on, then check that root can't come back. On Linux, keep
/// `CAP_NET_RAW` only if `dial` (a DIAL entry's target interface) can't be pinned without it.
///
/// # Errors
/// [`PrivilegeError`] if the switch is refused or does not take.
pub(crate) fn drop_to(
    credentials: Credentials,
    dial: Option<&InterfaceName>,
) -> Result<Outcome, PrivilegeError> {
    let effective = effective_ids();
    let switch = if effective.uid == 0 {
        // While still root: the permitted set is kept across the uid change.
        #[cfg(target_os = "linux")]
        caps::narrow_for_switch(dial.is_some())?;
        switch_to(credentials)?;
        Switch::Dropped
    } else if effective == credentials && real_ids() == credentials {
        Switch::AlreadyThatAccount
    } else {
        return Err(PrivilegeError::NotRoot(effective.uid));
    };
    #[cfg(target_os = "linux")]
    let dial_pin = caps::settle(dial)?;
    #[cfg(not(target_os = "linux"))]
    let dial_pin = {
        let _ = dial;
        DialPin::NoDial
    };
    #[cfg(any(target_os = "freebsd", target_os = "linux"))]
    {
        forbid_new_privileges()?;
        if !new_privileges_forbidden()? {
            return Err(PrivilegeError::NewPrivilegesAllowed);
        }
    }
    if effective_ids() != credentials || real_ids() != credentials || root_regainable() {
        return Err(PrivilegeError::StillPrivileged);
    }
    Ok(Outcome { switch, dial_pin })
}

/// Whether either id can go back to 0, checked both ways as OpenSSH's `permanently_set_uid` does.
/// Meaningful only once no capability allows it.
fn root_regainable() -> bool {
    // SAFETY: each takes a plain id; every call must fail.
    unsafe {
        libc::setgid(0) == 0
            || libc::setegid(0) == 0
            || libc::setuid(0) == 0
            || libc::seteuid(0) == 0
    }
}

/// From here on `execve` ignores setuid and setgid bits. One-way.
#[cfg(target_os = "linux")]
fn forbid_new_privileges() -> Result<(), PrivilegeError> {
    let (one, zero): (libc::c_ulong, libc::c_ulong) = (1, 0);
    // SAFETY: a prctl option that takes one integer argument.
    check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero) }).map_err(
        |source| PrivilegeError::Drop {
            step: "prctl(PR_SET_NO_NEW_PRIVS)",
            source,
        },
    )
}

#[cfg(target_os = "linux")]
fn new_privileges_forbidden() -> Result<bool, PrivilegeError> {
    let zero: libc::c_ulong = 0;
    // SAFETY: a prctl query that takes no argument.
    let rc = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, zero, zero, zero, zero) };
    check(rc).map_err(|source| PrivilegeError::Drop {
        step: "prctl(PR_GET_NO_NEW_PRIVS)",
        source,
    })?;
    Ok(rc == 1)
}

/// From here on `execve` ignores setuid and setgid bits. One-way; FreeBSD 13.1 and later.
#[cfg(target_os = "freebsd")]
fn forbid_new_privileges() -> Result<(), PrivilegeError> {
    let mut enable = libc::PROC_NO_NEW_PRIVS_ENABLE;
    procctl(
        "procctl(PROC_NO_NEW_PRIVS_CTL)",
        libc::PROC_NO_NEW_PRIVS_CTL,
        &mut enable,
    )
}

#[cfg(target_os = "freebsd")]
fn new_privileges_forbidden() -> Result<bool, PrivilegeError> {
    let mut status = 0;
    procctl(
        "procctl(PROC_NO_NEW_PRIVS_STATUS)",
        libc::PROC_NO_NEW_PRIVS_STATUS,
        &mut status,
    )?;
    Ok(status == libc::PROC_NO_NEW_PRIVS_ENABLE)
}

/// A `procctl` command on this process that reads or writes one int.
#[cfg(target_os = "freebsd")]
fn procctl(step: &'static str, command: c_int, value: &mut c_int) -> Result<(), PrivilegeError> {
    // SAFETY: id 0 under P_PID is the calling process; `value` is live for the call.
    check(unsafe { libc::procctl(libc::P_PID, 0, command, ptr::from_mut(value).cast()) })
        .map_err(|source| PrivilegeError::Drop { step, source })
}

/// Groups first: once the uid is gone, so is the right to change them.
fn switch_to(credentials: Credentials) -> Result<(), PrivilegeError> {
    let drop = |step, rc| check(rc).map_err(|source| PrivilegeError::Drop { step, source });
    // SAFETY: setgroups reads one gid from a live array.
    drop("setgroups", unsafe {
        libc::setgroups(1, &raw const credentials.gid)
    })?;
    // SAFETY: setgid/setuid take plain ids.
    drop("setgid", unsafe { libc::setgid(credentials.gid) })?;
    // SAFETY: as above.
    drop("setuid", unsafe { libc::setuid(credentials.uid) })
}

fn effective_ids() -> Credentials {
    // SAFETY: geteuid/getegid take no arguments and cannot fail.
    unsafe {
        Credentials {
            uid: libc::geteuid(),
            gid: libc::getegid(),
        }
    }
}

fn real_ids() -> Credentials {
    // SAFETY: getuid/getgid take no arguments and cannot fail.
    unsafe {
        Credentials {
            uid: libc::getuid(),
            gid: libc::getgid(),
        }
    }
}

fn user_by_name(name: &str) -> Result<Option<Credentials>, PrivilegeError> {
    let Ok(name) = CString::new(name) else {
        return Ok(None);
    };
    lookup(
        // SAFETY: every pointer is live for the call and `len` is the buffer's length.
        |entry, buf, len, found| unsafe { libc::getpwnam_r(name.as_ptr(), entry, buf, len, found) },
        account_of,
    )
}

fn user_by_id(uid: uid_t) -> Result<Option<Credentials>, PrivilegeError> {
    lookup(
        // SAFETY: as in user_by_name.
        |entry, buf, len, found| unsafe { libc::getpwuid_r(uid, entry, buf, len, found) },
        account_of,
    )
}

/// The uid and primary group a password entry names.
fn account_of(entry: &libc::passwd) -> Credentials {
    Credentials {
        uid: entry.pw_uid,
        gid: entry.pw_gid,
    }
}

fn group_by_name(name: &str) -> Result<Option<gid_t>, PrivilegeError> {
    let Ok(name) = CString::new(name) else {
        return Ok(None);
    };
    lookup(
        // SAFETY: as in user_by_name.
        |entry, buf, len, found| unsafe { libc::getgrnam_r(name.as_ptr(), entry, buf, len, found) },
        |entry: &libc::group| entry.gr_gid,
    )
}

/// Where a lookup buffer stops growing: far past any real account entry, short of unbounded.
const MAX_LOOKUP_BUFFER: usize = 1 << 20;

/// Run a reentrant account lookup, growing its buffer while it reports `ERANGE`, and keep only
/// what `pick` copies out: the entry's strings live in the buffer, which does not outlive this.
fn lookup<T, R>(
    call: impl Fn(*mut T, *mut c_char, usize, *mut *mut T) -> c_int,
    pick: impl Fn(&T) -> R,
) -> Result<Option<R>, PrivilegeError> {
    let mut len = 1024;
    loop {
        let mut buf: Vec<c_char> = vec![0; len];
        let mut entry = MaybeUninit::<T>::uninit();
        let mut found: *mut T = ptr::null_mut();
        let rc = call(entry.as_mut_ptr(), buf.as_mut_ptr(), len, &raw mut found);
        if rc == libc::ERANGE && len < MAX_LOOKUP_BUFFER {
            len *= 2;
            continue;
        }
        // POSIX lets "not found" come back as one of these rather than a null result (musl
        // says ENOENT when the database file itself is absent, as in a scratch image).
        match rc {
            0 => {}
            libc::ENOENT | libc::ESRCH | libc::EBADF | libc::EPERM => return Ok(None),
            _ => return Err(PrivilegeError::Lookup(io::Error::from_raw_os_error(rc))),
        }
        if found.is_null() {
            return Ok(None);
        }
        // SAFETY: a non-null result points at `entry`, which the call filled in.
        return Ok(Some(pick(unsafe { &*found })));
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::test_support::{Capability, skip};

    /// Set in a child [`run_in_children`] spawns: the mode it runs.
    pub(super) const CHILD_MODE: &str = "NETFLECTOR_TEST_DROP_MODE";
    /// The account the child processes switch to.
    pub(super) const TARGET: Credentials = Credentials {
        uid: 65534,
        gid: 65534,
    };

    /// Whether this process is root, where a real drop would de-privilege the whole test run.
    fn is_root() -> bool {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    /// Run the test named `test` again, once per mode in a child process of its own: a switch
    /// takes the whole process. `prepare` adjusts each child's command.
    pub(super) fn run_in_children(
        test: &str,
        modes: &[&str],
        prepare: impl Fn(&str, &mut Command),
    ) {
        if !is_root() {
            skip(Capability::Drop, "switching accounts needs root");
            return;
        }
        let exe = std::env::current_exe().expect("the test binary's path");
        for &mode in modes {
            let mut command = Command::new(&exe);
            command
                .args(["--exact", test, "--test-threads=1", "--nocapture"])
                .env(CHILD_MODE, mode);
            prepare(mode, &mut command);
            let output = command.output().expect("spawn the test binary");
            let report = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.status.success(), "mode {mode}:\n{report}");
            // A filter typo would pass by running nothing.
            assert!(
                report.contains("1 passed"),
                "mode {mode} ran no test:\n{report}"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "switches account through libc, which Miri cannot run")]
    fn the_switch_leaves_no_way_back_to_root() {
        if std::env::var(CHILD_MODE).is_ok() {
            assert_eq!(
                drop_to(TARGET, None).unwrap(),
                Outcome {
                    switch: Switch::Dropped,
                    dial_pin: DialPin::NoDial,
                }
            );
            assert_eq!((effective_ids(), real_ids()), (TARGET, TARGET));
            #[cfg(any(target_os = "freebsd", target_os = "linux"))]
            assert!(new_privileges_forbidden().unwrap());
            return;
        }
        run_in_children(
            "privileges::tests::the_switch_leaves_no_way_back_to_root",
            &["full"],
            |_, _| {},
        );
    }

    #[test]
    fn numbers_resolve_as_given() {
        let credentials = resolve(&"65534:65533".parse().unwrap()).unwrap();
        assert_eq!(
            credentials,
            Credentials {
                uid: 65534,
                gid: 65533
            }
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "calls the account database or process ids through libc, which Miri cannot run"
    )]
    fn a_name_resolves_through_the_account_database() {
        // Every target has `nobody`: 65534 on Linux and FreeBSD, -2 on macOS.
        let credentials = resolve(&"nobody".parse().unwrap()).unwrap();
        assert_ne!(credentials.uid, 0);
        assert_ne!(credentials.gid, 0);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "calls the account database or process ids through libc, which Miri cannot run"
    )]
    fn an_unknown_account_is_refused_by_name() {
        assert!(matches!(
            resolve(&"no-such-user-nf".parse().unwrap()),
            Err(PrivilegeError::UnknownUser(name)) if name == "no-such-user-nf"
        ));
        assert!(matches!(
            resolve(&"nobody:no-such-group-nf".parse().unwrap()),
            Err(PrivilegeError::UnknownGroup(name)) if name == "no-such-group-nf"
        ));
        // A bare number with no account behind it has no group to take.
        assert!(matches!(
            resolve(&"3999999".parse().unwrap()),
            Err(PrivilegeError::NoPrimaryGroup(3_999_999))
        ));
    }

    #[test]
    fn a_missing_account_database_reads_as_no_account() {
        // POSIX lets the *_r lookups report "not found" as one of these instead of a null result;
        // musl does, with ENOENT, where /etc/passwd is absent (a scratch container image).
        for code in [libc::ENOENT, libc::ESRCH, libc::EBADF, libc::EPERM] {
            let found = lookup(|_, _, _, _| code, |entry: &libc::passwd| entry.pw_uid).unwrap();
            assert_eq!(found, None, "errno {code}");
        }
        assert!(matches!(
            lookup(|_, _, _, _| libc::EIO, |entry: &libc::passwd| entry.pw_uid),
            Err(PrivilegeError::Lookup(_))
        ));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "calls the account database or process ids through libc, which Miri cannot run"
    )]
    fn root_is_refused_as_a_target() {
        for spec in ["0", "root", "0:0", "65534:0"] {
            assert!(
                matches!(
                    resolve(&spec.parse().unwrap()),
                    Err(PrivilegeError::Privileged)
                ),
                "{spec}"
            );
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "calls the account database or process ids through libc, which Miri cannot run"
    )]
    fn a_non_root_process_keeps_its_own_account_and_refuses_another() {
        if is_root() {
            return; // Covered end to end: a drop here would de-privilege the test run.
        }
        let own = real_ids();
        assert_eq!(
            drop_to(own, None).unwrap(),
            Outcome {
                switch: Switch::AlreadyThatAccount,
                dial_pin: DialPin::NoDial,
            }
        );
        let other = Credentials {
            uid: own.uid + 1,
            gid: own.gid,
        };
        assert!(
            matches!(drop_to(other, None), Err(PrivilegeError::NotRoot(uid)) if uid == own.uid)
        );
    }
}
