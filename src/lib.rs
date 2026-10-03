//! netflector: reflects link-local service traffic (Wake-on-LAN, mDNS, SSDP, WS-Discovery,
//! and an optional DIAL proxy) between two network interfaces. The binary is a thin shim
//! over [`run`].

mod capture;
mod cli;
mod config;
mod dispatch;
mod error;
mod interface;
mod linear_map;
mod logging;
mod memory_report;
mod net;
mod reactor;
mod reflector;
mod sys;
#[cfg(test)]
mod test_support;
mod unique_list;

pub use self::error::{Error, Result};
pub use self::logging::init as init_logging;

use std::ffi::OsString;
use std::path::Path;

use self::cli::Invocation;
use self::config::Config;
use self::dispatch::PacketDispatcher;
use self::reactor::Reactor;
use self::reflector::InterfaceMap;

/// Run what the command line asks for. `args` is `argv` without `argv[0]`; `--help` documents
/// the syntax.
///
/// # Errors
/// [`Error`] on a usage error, a configuration error, or a reactor failure.
pub fn run(args: &[OsString]) -> Result<()> {
    match cli::parse(args)? {
        Invocation::Help => {
            print!("{}", cli::HELP);
            Ok(())
        }
        Invocation::Version => {
            println!("netflector {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Invocation::CheckConfig(path) => check_config(path),
        Invocation::Run { path, join_groups } => reflect(path, join_groups),
    }
}

/// Parses and validates only: no capture is opened and no interface resolved, so it runs
/// unprivileged on a host without the configured interfaces (and cannot report a missing one).
/// The log level is left alone so `log_level = "off"` cannot swallow the answer.
fn check_config(path: Option<&Path>) -> Result<()> {
    let toml_text = path.map(config::read_config_file).transpose()?;
    let config = Config::from_sources(toml_text.as_deref(), sys::process_env())?;
    let count = config.reflectors.len();
    println!(
        "config ok: {count} reflector{}",
        if count == 1 { "" } else { "s" }
    );
    Ok(())
}

/// # Errors
/// Configuration loading or validation, capture setup, or the reactor.
fn reflect(path: Option<&Path>, join_groups: bool) -> Result<()> {
    let toml_text = path.map(config::read_config_file).transpose()?;
    // Not std::env::vars: it segfaults in statically linked FreeBSD binaries (see process_env).
    let env = sys::process_env();

    // Log level first, so the full parse below logs at the configured verbosity.
    let level = config::resolve_log_level(toml_text.as_deref(), &env)?;
    logging::set_level(level);
    log::debug!("log level {level:?}");
    log::info!("netflector {} starting", env!("CARGO_PKG_VERSION"));
    if let Some(path) = path {
        log::debug!(
            "loading configuration from {} with NETFLECTOR_* overrides",
            path.display()
        );
    } else {
        log::debug!("loading configuration from NETFLECTOR_* environment only");
    }

    sys::raise_file_limit();

    let mut config = Config::from_sources(toml_text.as_deref(), env)?;
    fit_to_host(&mut config)?;
    let count = config.reflectors.len();
    log::info!(
        "loaded {count} reflector{}",
        if count == 1 { "" } else { "s" }
    );

    let mut dispatcher = if join_groups {
        PacketDispatcher::new()
    } else {
        log::warn!(
            "--no-join: multicast groups are not joined; group traffic reaches the captures \
             only where the link delivers it without a membership"
        );
        PacketDispatcher::without_group_joins()
    };
    let interfaces = open_captures(&config, &mut dispatcher)?;
    for reflector in &config.reflectors {
        log_mtu_info(reflector, &interfaces, &dispatcher);
        build_reflector(reflector, &interfaces, &mut dispatcher)?;
        if reflector.bidirectional {
            build_reflector(&reflector.reversed(), &interfaces, &mut dispatcher)?;
        }
    }

    if let Some(interval) = config.counter_interval {
        log::info!(
            "packet counters enabled; reporting every {}s",
            interval.as_secs()
        );
        dispatcher.enable_counter_report(interval, std::time::Instant::now());
    }

    let mut reactor = Reactor::new()?;
    let watches = dispatcher.capture_watches();
    reactor.register_with_fds(Box::new(dispatcher), &watches)?;
    if let Some(interval) = config.debug_memory_interval {
        log::info!(
            "memory diagnostics enabled; reporting every {}s",
            interval.as_secs()
        );
        memory_report::log_report();
    }
    // Registered even without an interval: it still answers a SIGUSR1 dump.
    reactor.register(Box::new(memory_report::MemoryReporter::new(
        config.debug_memory_interval,
        std::time::Instant::now(),
    )));
    log::info!("running; press Ctrl-C or send SIGTERM to stop");
    reactor.run()?;
    if config.debug_memory_interval.is_some() {
        memory_report::log_report();
    }
    log::info!("stopped");
    Ok(())
}

/// Before anything uses the configuration.
///
/// # Errors
/// An entry that needs IPv6 for what it was configured to do.
fn fit_to_host(config: &mut Config) -> Result<()> {
    if !sys::has_ipv6() {
        log::info!(
            "this host has no IPv6 stack; entries with the default address family reflect \
             IPv4 only"
        );
        config.fall_back_to_ipv4()?;
    }
    Ok(())
}

fn build_reflector(
    reflector: &config::Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<()> {
    use crate::reflector::{mdns, ssdp, udp, wol, wsd};
    for build in [wol::build, mdns::build, ssdp::build, wsd::build, udp::build] {
        build(reflector, interfaces, dispatcher)
            .map_err(|e| Error::reflector(reflector.name.as_str(), e))?;
    }
    Ok(())
}

/// A capture that can't open aborts startup: a daemon that looks healthy but reflects nothing
/// is worse.
fn open_captures(config: &Config, dispatcher: &mut PacketDispatcher) -> Result<InterfaceMap> {
    let mut interfaces = InterfaceMap::default();
    for reflector in &config.reflectors {
        for name in [&reflector.source_if, &reflector.target_if] {
            if interfaces.key_for(name).is_some() {
                continue;
            }
            let key = dispatcher
                .open_capture(name)
                .map_err(|e| Error::capture(name, e))?;
            interfaces.insert(name.clone(), key);
        }
    }
    Ok(interfaces)
}

/// Info, not warn: an actual oversize drop warns at the send.
fn log_mtu_info(
    reflector: &config::Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &PacketDispatcher,
) {
    let (source_if, target_if) = (&reflector.source_if, &reflector.target_if);
    let (Ok(source_key), Ok(target_key)) =
        (interfaces.require(source_if), interfaces.require(target_if))
    else {
        return; // the protocol builders surface the unknown-interface error
    };
    let (Some(source), Some(target)) = (
        dispatcher.interface_mtu(source_key),
        dispatcher.interface_mtu(target_key),
    ) else {
        return;
    };
    let ceiling = u32::try_from(net::MAX_MTU).expect("the MTU ceiling fits a u32");
    for (if_name, mtu) in [(source_if, source), (target_if, target)] {
        if mtu > ceiling {
            log::info!(
                "{}: {if_name} MTU {mtu} exceeds the {ceiling}-byte ceiling; larger \
                 packets are not reflected",
                reflector.name.as_str(),
            );
        }
    }
    if source != target && source.min(target) <= ceiling {
        log::info!(
            "{}: MTU mismatch: {source_if} has {source}, {target_if} has {target}; packets larger \
             than {} bytes cannot cross toward the smaller side and are dropped",
            reflector.name.as_str(),
            source.min(target),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_config_accepts_a_valid_file_and_rejects_a_bad_one() {
        // The whole point of --check-config is that it runs where the interfaces do not exist, so
        // this must pass on any host, unprivileged, with no vtnet0 anywhere in sight.
        let good = "[reflectors.tv]\nsource_if = \"vtnet0\"\ntarget_if = \"vtnet1\"\nmdns = true\n";
        let config = Config::from_sources(Some(good), Vec::new()).unwrap();
        assert_eq!(config.reflectors.len(), 1);

        // An entry that enables no protocol reflects nothing; that is a config error, not a daemon
        // that quietly does nothing.
        let bad = "[reflectors.tv]\nsource_if = \"vtnet0\"\ntarget_if = \"vtnet1\"\n";
        assert!(Config::from_sources(Some(bad), Vec::new()).is_err());
    }

    // Under "default" IPv6 is best-effort: on a host with no IPv6 stack the entry reflects IPv4
    // instead of failing startup.
    #[cfg(target_os = "linux")]
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_default_entry_starts_on_a_host_without_an_ipv6_stack() {
        use crate::interface::LOOPBACK_IFACE;
        use crate::test_support::{Tun, loopback_lock};

        let _serial = loopback_lock();
        let Some(tun) = Tun::create() else {
            return;
        };
        assert!(tun.add_address("10.99.202.1/24"));
        let mut config = Config::from_sources(
            Some(&format!(
                "[reflectors.a]\nsource_if = \"{LOOPBACK_IFACE}\"\ntarget_if = \"{}\"\n\
                 mdns = true\n",
                tun.name
            )),
            std::iter::empty(),
        )
        .expect("a valid configuration");
        // A thread of its own: the seccomp filter binds the thread that installs it and dies
        // with it.
        std::thread::spawn(move || {
            deny_ipv6_sockets();
            fit_to_host(&mut config)?;
            let mut dispatcher = PacketDispatcher::new();
            let interfaces = open_captures(&config, &mut dispatcher)?;
            build_reflector(&config.reflectors[0], &interfaces, &mut dispatcher)
        })
        .join()
        .expect("the startup thread panicked")
        .expect("a default entry starts without IPv6");
    }

    /// From here on this thread's `socket(AF_INET6, ..)` fails with `EAFNOSUPPORT`, as on a
    /// kernel booted with `ipv6.disable=1`.
    #[cfg(target_os = "linux")]
    fn deny_ipv6_sockets() {
        use libc::{
            BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, c_ulong, sock_filter,
            sock_fprog,
        };

        // `struct seccomp_data`: `nr` at 0, the low word of `args[0]` at 16 or 20.
        const NR: u32 = 0;
        const ARG0: u32 = if cfg!(target_endian = "big") { 20 } else { 16 };
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
                u32::try_from(libc::SYS_socket).unwrap(),
                0,
                3,
            ),
            op(BPF_LD | BPF_W | BPF_ABS, ARG0, 0, 0),
            op(
                BPF_JMP | BPF_JEQ | BPF_K,
                u32::try_from(libc::AF_INET6).unwrap(),
                0,
                1,
            ),
            op(
                BPF_RET | BPF_K,
                libc::SECCOMP_RET_ERRNO | u32::try_from(libc::EAFNOSUPPORT).unwrap(),
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
                std::io::Error::last_os_error()
            );
        }
    }
}
