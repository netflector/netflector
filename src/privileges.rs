//! Dropping root once the captures are open (`--user`).

use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::ptr;
use std::str::FromStr;

use libc::{c_char, c_int, gid_t, uid_t};
use thiserror::Error;

use crate::sys::check;

/// One side of a `--user` spec: a name to look up, or a number taken as is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Principal {
    Name(String),
    Id(u32),
}

impl Principal {
    fn parse(text: &str) -> Option<Self> {
        if text.is_empty() {
            return None;
        }
        Some(match text.parse() {
            Ok(id) => Self::Id(id),
            Err(_) => Self::Name(text.to_owned()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected USER or USER:GROUP, each a name or a number")]
pub(crate) struct ParseRunAsError;

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
}

/// The account `--user` names: a user and optionally a group, each by name or number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunAs {
    user: Principal,
    group: Option<Principal>,
}

impl RunAs {
    /// A named user brings its primary group unless the spec names one; a bare uid takes the
    /// group of the account behind it.
    ///
    /// # Errors
    /// [`PrivilegeError`] for an unknown account, or one that is root.
    pub(crate) fn resolve(&self) -> Result<Credentials, PrivilegeError> {
        // A number is taken as is: the database is consulted only for a name, or for the group
        // of a bare uid, so a spec in numbers runs where there is no /etc/passwd at all.
        let (uid, primary) = match &self.user {
            Principal::Id(uid) => (*uid, None),
            Principal::Name(name) => {
                let account =
                    user_by_name(name)?.ok_or_else(|| PrivilegeError::UnknownUser(name.clone()))?;
                (account.uid, Some(account.gid))
            }
        };
        let gid = match (&self.group, primary) {
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
}

impl FromStr for RunAs {
    type Err = ParseRunAsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (user, group) = match s.split_once(':') {
            Some((user, group)) => (user, Some(group)),
            None => (s, None),
        };
        Ok(Self {
            user: Principal::parse(user).ok_or(ParseRunAsError)?,
            group: group
                .map(|group| Principal::parse(group).filter(|_| !group.contains(':')))
                .map(|group| group.ok_or(ParseRunAsError))
                .transpose()?,
        })
    }
}

/// What [`drop_to`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Switch {
    /// Started as root: now that account, supplementary groups cleared, root not regainable.
    Dropped,
    /// Started as that account already: nothing changed, and its groups and capabilities are
    /// whatever the launcher gave it.
    AlreadyThatAccount,
}

/// Started as root, switch the whole process to `credentials`, supplementary groups cleared, and
/// prove root is gone: every id reads back as asked and `setuid(0)` fails. Not started as root,
/// accept only running as that account already, and change nothing.
///
/// # Errors
/// [`PrivilegeError`] if the switch is refused or does not take.
pub(crate) fn drop_to(credentials: Credentials) -> Result<Switch, PrivilegeError> {
    let Credentials { uid, gid } = credentials;
    let effective = effective_ids();
    if effective.uid != 0 {
        return if effective == credentials && real_ids() == credentials {
            Ok(Switch::AlreadyThatAccount)
        } else {
            Err(PrivilegeError::NotRoot(effective.uid))
        };
    }
    let drop = |step, rc| check(rc).map_err(|source| PrivilegeError::Drop { step, source });
    // Group first: once the uid is gone, so is the right to change groups.
    // SAFETY: setgroups reads one gid from a live array.
    drop("setgroups", unsafe {
        libc::setgroups(1, &raw const credentials.gid)
    })?;
    // SAFETY: setgid/setuid take plain ids.
    drop("setgid", unsafe { libc::setgid(gid) })?;
    // SAFETY: as above.
    drop("setuid", unsafe { libc::setuid(uid) })?;
    // SAFETY: as above; this call must fail.
    let regained = unsafe { libc::setuid(0) } == 0;
    if regained || effective_ids() != credentials || real_ids() != credentials {
        return Err(PrivilegeError::StillPrivileged);
    }
    Ok(Switch::Dropped)
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
    use super::*;

    /// Whether this process is root, where a real drop would de-privilege the whole test run.
    fn is_root() -> bool {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn a_spec_is_a_user_and_an_optional_group_by_name_or_number() {
        assert_eq!(
            "netflector".parse::<RunAs>().unwrap(),
            RunAs {
                user: Principal::Name("netflector".to_owned()),
                group: None,
            }
        );
        assert_eq!(
            "65534:65534".parse::<RunAs>().unwrap(),
            RunAs {
                user: Principal::Id(65534),
                group: Some(Principal::Id(65534)),
            }
        );
        assert_eq!(
            "netflector:nogroup".parse::<RunAs>().unwrap(),
            RunAs {
                user: Principal::Name("netflector".to_owned()),
                group: Some(Principal::Name("nogroup".to_owned())),
            }
        );
        for bad in ["", ":", "user:", ":group", "a:b:c"] {
            assert_eq!(bad.parse::<RunAs>(), Err(ParseRunAsError), "{bad:?}");
        }
    }

    #[test]
    fn numbers_resolve_as_given() {
        let credentials = "65534:65533".parse::<RunAs>().unwrap().resolve().unwrap();
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
        let credentials = "nobody".parse::<RunAs>().unwrap().resolve().unwrap();
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
            "no-such-user-nf".parse::<RunAs>().unwrap().resolve(),
            Err(PrivilegeError::UnknownUser(name)) if name == "no-such-user-nf"
        ));
        assert!(matches!(
            "nobody:no-such-group-nf".parse::<RunAs>().unwrap().resolve(),
            Err(PrivilegeError::UnknownGroup(name)) if name == "no-such-group-nf"
        ));
        // A bare number with no account behind it has no group to take.
        assert!(matches!(
            "3999999".parse::<RunAs>().unwrap().resolve(),
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
                    spec.parse::<RunAs>().unwrap().resolve(),
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
        assert_eq!(drop_to(own).unwrap(), Switch::AlreadyThatAccount);
        let other = Credentials {
            uid: own.uid + 1,
            gid: own.gid,
        };
        assert!(matches!(drop_to(other), Err(PrivilegeError::NotRoot(uid)) if uid == own.uid));
    }
}
