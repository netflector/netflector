//! Registry of minted DIAL proxies, one per device, shared by the SSDP advertisement and
//! search-response paths.

use std::net::SocketAddrV4;
use std::time::Instant;

use crate::linear_map::LinearMap;
use crate::reactor::{HandlerKey, Reactor};

use super::CaptureKey;

/// Daemon-wide cap on minted DIAL proxies. At the cap a new device's `LOCATION` is reflected
/// unchanged rather than evicting a live proxy. Not per device: the endpoint comes from the
/// advertisement's own `LOCATION`, so an attacker names a fresh address per mint.
const MAX_DIAL_PROXIES: usize = 64;

/// The target is in the key: two pairs sharing a source both see one endpoint when their target
/// segments overlap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct DialProxyKey {
    pub(crate) source: CaptureKey,
    pub(crate) target: CaptureKey,
    pub(crate) endpoint: SocketAddrV4,
}

struct DialEntry {
    /// Stale once the proxy is evicted; the reactor no longer knows it.
    handler: HandlerKey,
    /// The source-side description listener spliced into the device's `LOCATION`.
    desc_addr: SocketAddrV4,
    /// Eviction deadline, refreshed to each advertisement's `max-age`.
    desc_grace: Instant,
}

/// An evicted proxy's entry is pruned on the next lookup or capacity check.
pub(crate) struct DialContext {
    proxies: LinearMap<DialProxyKey, DialEntry>,
}

impl DialContext {
    pub(crate) fn new() -> Self {
        Self {
            proxies: LinearMap::new(),
        }
    }

    /// The live proxy's listener address for `key`, its grace refreshed to `desc_grace`; a stale
    /// entry (proxy evicted) is pruned and reads as absent.
    pub(crate) fn lookup(
        &mut self,
        key: DialProxyKey,
        reactor: &Reactor,
        desc_grace: Instant,
    ) -> Option<SocketAddrV4> {
        if let Some(entry) = self.proxies.get_mut(&key)
            && reactor.is_registered(entry.handler)
        {
            entry.desc_grace = desc_grace;
            return Some(entry.desc_addr);
        }
        if self.proxies.remove(&key).is_some() {
            log::trace!("dial: pruning the stale proxy entry for {}", key.endpoint);
        }
        None
    }

    pub(crate) fn has_capacity(&mut self, reactor: &Reactor) -> bool {
        self.proxies.retain(|_, p| reactor.is_registered(p.handler));
        self.proxies.len() < MAX_DIAL_PROXIES
    }

    pub(crate) fn insert(
        &mut self,
        key: DialProxyKey,
        handler: HandlerKey,
        desc_addr: SocketAddrV4,
        desc_grace: Instant,
    ) {
        self.proxies.insert(
            key,
            DialEntry {
                handler,
                desc_addr,
                desc_grace,
            },
        );
    }

    pub(crate) fn next_grace(&self) -> Option<Instant> {
        self.proxies.iter().map(|(_, p)| p.desc_grace).min()
    }

    fn evict_where(
        &mut self,
        reactor: &mut Reactor,
        reason: &str,
        evict: impl Fn(&DialProxyKey, &DialEntry) -> bool,
    ) {
        self.proxies.retain(|key, p| {
            if evict(key, p) {
                match reactor.unregister(p.handler) {
                    Ok(_) => log::debug!("dial: evicted the proxy for {} {reason}", key.endpoint),
                    Err(e) => {
                        log::warn!(
                            "dial: evicting the proxy for {} {reason} failed: {e}",
                            key.endpoint
                        );
                    }
                }
                false // drop the entry even if the teardown failed
            } else {
                reactor.is_registered(p.handler) // drop an already-evicted entry
            }
        });
    }

    pub(crate) fn sweep(&mut self, now: Instant, reactor: &mut Reactor) {
        self.evict_where(reactor, "past its grace", |_, p| now >= p.desc_grace);
    }

    /// An address move or recreation on a proxy's source or target strands its listeners or its
    /// device-connect egress; it re-mints on the next advertisement.
    pub(crate) fn evict_on_interface_change(
        &mut self,
        reactor: &mut Reactor,
        changed: &[CaptureKey],
        reason: &str,
    ) {
        self.evict_where(reactor, reason, |key, _| {
            changed.contains(&key.source) || changed.contains(&key.target)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl DialContext {
        /// The number of recorded proxies: a seam for the DIAL hook's tests in `reflector::dial`.
        pub(crate) fn proxy_count(&self) -> usize {
            self.proxies.len()
        }

        /// The recorded proxies' handler keys: a seam to simulate an eviction.
        pub(crate) fn handler_keys(&self) -> Vec<HandlerKey> {
            self.proxies.iter().map(|(_, p)| p.handler).collect()
        }

        /// The recorded grace for `key`: a seam to assert a re-advertisement refreshed it.
        pub(crate) fn grace_of(&self, key: DialProxyKey) -> Option<Instant> {
            self.proxies.get(&key).map(|p| p.desc_grace)
        }
    }

    use std::time::Duration;

    use crate::test_support::NoopHandler;

    fn ep(n: u8) -> SocketAddrV4 {
        SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, n), 8008)
    }

    fn key(s: u32, t: u32, e: SocketAddrV4) -> DialProxyKey {
        DialProxyKey {
            source: CaptureKey(s),
            target: CaptureKey(t),
            endpoint: e,
        }
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn next_grace_reports_the_soonest_or_none_when_empty() {
        let mut reactor = Reactor::new().unwrap();
        let mut ctx = DialContext::new();
        assert_eq!(ctx.next_grace(), None);

        let base = Instant::now();
        let hk1 = reactor.register(Box::new(NoopHandler));
        ctx.insert(key(0, 1, ep(1)), hk1, ep(9), base + Duration::from_secs(10));
        let hk2 = reactor.register(Box::new(NoopHandler));
        ctx.insert(key(0, 1, ep(2)), hk2, ep(9), base + Duration::from_secs(5));
        assert_eq!(ctx.next_grace(), Some(base + Duration::from_secs(5)));
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn lookup_finds_a_live_proxy_and_prunes_an_evicted_one() {
        let mut reactor = Reactor::new().unwrap();
        let mut ctx = DialContext::new();
        let hk = reactor.register(Box::new(NoopHandler));
        let base = Instant::now();
        ctx.insert(key(0, 1, ep(1)), hk, ep(9), base);

        // Live: found, and its grace is refreshed to the new deadline.
        let refreshed = base + Duration::from_secs(30);
        assert_eq!(
            ctx.lookup(key(0, 1, ep(1)), &reactor, refreshed),
            Some(ep(9))
        );
        assert_eq!(ctx.grace_of(key(0, 1, ep(1))), Some(refreshed));

        // Evicted: the stale entry is pruned and reported absent.
        reactor.unregister(hk).unwrap();
        assert_eq!(ctx.lookup(key(0, 1, ep(1)), &reactor, base), None);
        assert_eq!(ctx.proxy_count(), 0);
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn lookup_does_not_cross_targets() {
        // Only reachable when the two target segments carry the same address.
        let mut reactor = Reactor::new().unwrap();
        let mut ctx = DialContext::new();
        let base = Instant::now();
        let hk = reactor.register(Box::new(NoopHandler));
        ctx.insert(key(0, 1, ep(1)), hk, ep(9), base);

        assert_eq!(ctx.lookup(key(0, 1, ep(1)), &reactor, base), Some(ep(9)));
        assert_eq!(
            ctx.lookup(key(0, 2, ep(1)), &reactor, base),
            None,
            "a different target is a different proxy"
        );
    }

    /// Insert a live proxy per index in `which`, each with its own endpoint.
    fn fill(ctx: &mut DialContext, reactor: &mut Reactor, which: std::ops::Range<usize>) {
        let grace = Instant::now() + Duration::from_mins(1);
        for i in which {
            let hk = reactor.register(Box::new(NoopHandler));
            let ep = SocketAddrV4::new(
                std::net::Ipv4Addr::new(10, 0, 0, u8::try_from(i).unwrap()),
                8008,
            );
            ctx.insert(key(0, 1, ep), hk, ep, grace);
        }
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn the_cap_refuses_a_further_mint() {
        let mut reactor = Reactor::new().unwrap();
        let mut ctx = DialContext::new();
        fill(&mut ctx, &mut reactor, 0..MAX_DIAL_PROXIES - 1);
        assert!(ctx.has_capacity(&reactor));

        fill(
            &mut ctx,
            &mut reactor,
            MAX_DIAL_PROXIES - 1..MAX_DIAL_PROXIES,
        );
        assert_eq!(ctx.proxy_count(), MAX_DIAL_PROXIES);
        assert!(!ctx.has_capacity(&reactor));
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn capacity_prunes_evicted_entries_before_checking() {
        let mut reactor = Reactor::new().unwrap();
        let mut ctx = DialContext::new();
        fill(&mut ctx, &mut reactor, 0..MAX_DIAL_PROXIES);
        assert!(!ctx.has_capacity(&reactor));

        reactor.unregister(ctx.handler_keys()[0]).unwrap();
        assert!(ctx.has_capacity(&reactor));
        assert_eq!(
            ctx.proxy_count(),
            MAX_DIAL_PROXIES - 1,
            "the dead entry is gone, not merely skipped"
        );
    }
}
