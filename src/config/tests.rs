use super::*;

fn from_toml(text: &str) -> Result<Config, ConfigError> {
    Config::from_sources(Some(text), Vec::<(String, String)>::new())
}

fn err(text: &str) -> ConfigError {
    from_toml(text).unwrap_err()
}

// Every TOML block in the README is a whole configuration the checks accept.
#[test]
fn the_readme_examples_are_valid_configurations() {
    let readme = include_str!("../../README.md");
    let blocks: Vec<&str> = readme
        .split("```toml\n")
        .skip(1)
        .map(|rest| rest.split("```").next().unwrap_or(""))
        .collect();
    assert!(blocks.len() >= 4, "the README lost its examples");
    for block in blocks {
        from_toml(block).unwrap_or_else(|e| panic!("README example does not load: {e}\n{block}"));
    }
}

#[test]
fn minimal_reflector_uses_defaults() {
    let cfg = from_toml(
        r#"
            [reflectors.discovery]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            "#,
    )
    .unwrap();
    assert_eq!(cfg.log_level, LogLevel::Info);
    assert!(cfg.debug_memory_interval.is_none());
    assert_eq!(cfg.reflectors.len(), 1);
    let r = &cfg.reflectors[0];
    assert_eq!(r.name.as_str(), "discovery");
    assert_eq!(r.source_if.as_str(), "lan");
    assert_eq!(r.target_if.as_str(), "iot");
    assert!(r.mdns);
    assert!(r.macs.is_none());
    assert_eq!(r.address_family, AddressFamily::Default);
    assert!(r.wol.is_none());
    assert!(r.ssdp.is_none());
    assert!(!r.wsd);
}

#[test]
fn wsd_reflector_parses() {
    let cfg = from_toml(
        r#"
            [reflectors.cameras]
            source_if = "lan"
            target_if = "cams"
            wsd = true
            "#,
    )
    .unwrap();
    let r = &cfg.reflectors[0];
    assert!(r.wsd);
    assert!(!r.mdns);
    assert!(r.wol.is_none());
    assert!(r.ssdp.is_none());
    assert!(!r.bidirectional);
}

#[test]
fn wol_relays_ports_7_and_9_by_default() {
    let cfg = from_toml(
        r#"
            [reflectors.pc]
            source_if = "lan"
            target_if = "iot"
            wol = true
            "#,
    )
    .unwrap();
    let ports = &cfg.reflectors[0].wol.as_ref().unwrap().ports;
    assert_eq!(ports.iter().map(|p| p.get()).collect::<Vec<_>>(), [7, 9]);
}

#[test]
fn udp_relay_parses() {
    let cfg = from_toml(
        r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003]
            udp_groups = ["239.255.90.90"]
            udp_broadcast = true
            "#,
    )
    .unwrap();
    let udp = cfg.reflectors[0].udp.as_ref().unwrap();
    assert_eq!(
        udp.ports.iter().map(|p| p.get()).collect::<Vec<_>>(),
        [9003]
    );
    assert_eq!(
        udp.groups.as_ref().unwrap().to_vec(),
        ["239.255.90.90".parse::<IpAddr>().unwrap()]
    );
    assert!(udp.broadcast);
    assert!(cfg.reflectors[0].wol.is_none());
}

#[test]
fn peers_parse_and_swap_with_the_direction() {
    let cfg = from_toml(
        r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "wg0"
            udp_ports = [9003]
            udp_groups = ["239.255.90.90"]
            target_peers = ["10.10.10.2", "10.10.10.3"]
            bidirectional = true
            "#,
    )
    .unwrap();
    let roon = &cfg.reflectors[0];
    assert!(roon.source_peers.is_none());
    assert_eq!(roon.target_peers.as_deref().map(<[IpAddr]>::len), Some(2));
    let reversed = roon.reversed();
    assert_eq!(reversed.source_peers, roon.target_peers);
    assert!(reversed.target_peers.is_none());
}

#[test]
fn mdns_answers_cannot_go_to_peers() {
    let entry = |extra: &str| {
        format!("[reflectors.a]\nsource_if = \"lan\"\ntarget_if = \"wg0\"\nmdns = true\n{extra}")
    };
    assert!(matches!(
        err(&entry("source_peers = [\"192.0.2.2\"]\n")),
        ConfigError::MdnsAnswersToPeers {
            param: "source_peers",
            ..
        }
    ));
    assert!(matches!(
        err(&entry(
            "target_peers = [\"10.10.10.2\"]\nbidirectional = true\n"
        )),
        ConfigError::MdnsAnswersToPeers {
            param: "target_peers",
            ..
        }
    ));
    // Queries may go to peers: a device answers a direct unicast query.
    assert!(from_toml(&entry("target_peers = [\"10.10.10.2\"]\n")).is_ok());
}

#[test]
fn peer_must_be_of_a_used_family() {
    let text = r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "wg0"
            address_family = "ipv4"
            mdns = true
            target_peers = ["fd00::2"]
        "#;
    assert!(matches!(err(text), ConfigError::PeerFamily { .. }));
}

#[test]
fn macs_need_a_protocol_that_applies_them() {
    let text = r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            macs = ["00:00:00:00:00:01"]
            udp_ports = [9003]
            udp_broadcast = true
        "#;
    assert!(matches!(err(text), ConfigError::MacsUnused { .. }));
    let cfg = from_toml(
        r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            macs = ["00:00:00:00:00:01"]
            wol = true
            udp_ports = [9003]
            udp_broadcast = true
            "#,
    )
    .unwrap();
    assert!(cfg.reflectors[0].macs.is_some());
}

#[test]
fn udp_relay_needs_ports_and_a_destination() {
    // Groups or broadcast without ports: nothing says which datagrams to relay.
    let text = r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            udp_groups = ["239.255.90.90"]
        "#;
    assert!(matches!(
        err(text),
        ConfigError::UdpRelayWithoutPorts { .. }
    ));
    // Ports without groups or broadcast: nothing to capture.
    let text = r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003]
        "#;
    assert!(matches!(
        err(text),
        ConfigError::UdpRelayNoDestination { .. }
    ));
}

#[test]
fn udp_group_must_be_of_a_used_family() {
    let text = r#"
            [reflectors.sync]
            source_if = "lan"
            target_if = "iot"
            address_family = "ipv4"
            udp_ports = [21027]
            udp_groups = ["ff12::8384"]
        "#;
    assert!(matches!(err(text), ConfigError::UdpGroupFamily { .. }));
}

#[test]
fn udp_broadcast_needs_ipv4() {
    let text = r#"
            [reflectors.sync]
            source_if = "lan"
            target_if = "iot"
            address_family = "ipv6"
            udp_ports = [21027]
            udp_groups = ["ff12::8384"]
            udp_broadcast = true
        "#;
    assert!(matches!(err(text), ConfigError::UdpBroadcastFamily { .. }));
}

#[test]
fn udp_relay_on_a_group_of_the_entrys_own_protocol_rejected() {
    let text = r#"
            [reflectors.lan]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            udp_ports = [5353]
            udp_groups = ["224.0.0.251"]
        "#;
    assert!(matches!(
        err(text),
        ConfigError::UdpRelayDuplicates {
            port: 5353,
            protocol: Protocol::Mdns,
            ..
        }
    ));
    // Wake-on-LAN captures every destination on its ports.
    let text = r#"
            [reflectors.lan]
            source_if = "lan"
            target_if = "iot"
            wol = true
            udp_ports = [9]
            udp_groups = ["239.255.90.90"]
        "#;
    assert!(matches!(
        err(text),
        ConfigError::UdpRelayDuplicates {
            port: 9,
            protocol: Protocol::Wol,
            ..
        }
    ));
}

#[test]
fn udp_relay_off_the_entrys_own_groups_parses() {
    // mDNS never captures a broadcast, so the relay on its port duplicates nothing.
    let cfg = from_toml(
        r#"
            [reflectors.lan]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            udp_ports = [5353]
            udp_broadcast = true
            "#,
    )
    .unwrap();
    assert!(cfg.reflectors[0].udp.is_some());
}

#[test]
fn bidirectional_reflector_parses_and_reverses() {
    let cfg = from_toml(
        r#"
            [reflectors.lan]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            bidirectional = true
            "#,
    )
    .unwrap();
    let r = &cfg.reflectors[0];
    assert!(r.bidirectional);
    let reversed = r.reversed();
    assert_eq!(reversed.source_if, r.target_if);
    assert_eq!(reversed.target_if, r.source_if);
    assert_eq!(reversed.name, r.name);
    assert!(reversed.mdns);
}

#[test]
fn full_reflector_parses() {
    let cfg = from_toml(
        r#"
            log_level = "DEBUG"
            debug_memory_interval_secs = 30

            [reflectors.tv]
            source_if = "en0"
            target_if = "lo0"
            macs = ["B0:37:95:C5:60:BE"]
            wol = true
            mdns = true
            ssdp = true
            dial = true
            wol_ports = [7, 9, 4000]
            address_family = "dual"
            "#,
    )
    .unwrap();
    assert_eq!(cfg.log_level, LogLevel::Debug);
    assert_eq!(cfg.debug_memory_interval, Some(Duration::from_secs(30)));
    assert_eq!(cfg.reflectors.len(), 1);
    let r = &cfg.reflectors[0];
    assert_eq!(r.name.as_str(), "tv");
    assert_eq!(r.source_if.as_str(), "en0");
    assert_eq!(r.target_if.as_str(), "lo0");
    let macs = r.macs.as_ref().unwrap();
    assert_eq!(macs.len(), 1);
    assert_eq!(macs[0].to_string(), "b0:37:95:c5:60:be");
    let wol = r.wol.as_ref().unwrap();
    assert!(r.mdns);
    let ssdp = r.ssdp.unwrap();
    assert!(ssdp.dial);
    assert_eq!(
        wol.ports.iter().map(|p| p.get()).collect::<Vec<_>>(),
        [7, 9, 4000]
    );
    assert_eq!(r.address_family, AddressFamily::Dual);
}

#[test]
fn counter_interval_parses_and_zero_disables() {
    // A positive interval becomes a Duration; 0 disables it, as does omitting the key.
    let toml = |secs: &str| {
        format!(
            r#"
                {secs}
                [reflectors.d]
                source_if = "a"
                target_if = "b"
                mdns = true
                "#
        )
    };
    assert_eq!(
        from_toml(&toml("counters_interval_secs = 30"))
            .unwrap()
            .counter_interval,
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        from_toml(&toml("counters_interval_secs = 0"))
            .unwrap()
            .counter_interval,
        None
    );
    assert_eq!(from_toml(&toml("")).unwrap().counter_interval, None);
}

#[test]
fn debug_memory_interval_parses_and_zero_disables() {
    // A positive interval becomes a Duration; 0 disables it, as does omitting the key.
    let toml = |secs: &str| {
        format!(
            r#"
                {secs}
                [reflectors.d]
                source_if = "a"
                target_if = "b"
                mdns = true
                "#
        )
    };
    assert_eq!(
        from_toml(&toml("debug_memory_interval_secs = 30"))
            .unwrap()
            .debug_memory_interval,
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        from_toml(&toml("debug_memory_interval_secs = 0"))
            .unwrap()
            .debug_memory_interval,
        None
    );
    assert_eq!(from_toml(&toml("")).unwrap().debug_memory_interval, None);
}

#[test]
fn an_over_large_interval_is_rejected_by_field() {
    // Past the cap is a typo that would overflow the reporter's Instant+Duration deadline and panic
    // at startup; reject it, naming the key, rather than accept it. The cap itself is valid.
    let toml = |line: &str| {
        format!(
            r#"
                {line}
                [reflectors.d]
                source_if = "a"
                target_if = "b"
                mdns = true
                "#
        )
    };
    let too_big = MAX_INTERVAL_SECS + 1;
    assert!(matches!(
        from_toml(&toml(&format!("debug_memory_interval_secs = {too_big}"))),
        Err(ConfigError::IntervalTooLarge { field: "debug_memory_interval_secs", secs, .. })
            if secs == too_big
    ));
    assert!(matches!(
        from_toml(&toml(&format!("counters_interval_secs = {too_big}"))),
        Err(ConfigError::IntervalTooLarge {
            field: "counters_interval_secs",
            ..
        })
    ));
    // The cap itself is accepted, for both keys.
    let at_cap = from_toml(&toml(&format!(
        "debug_memory_interval_secs = {MAX_INTERVAL_SECS}\n\
             counters_interval_secs = {MAX_INTERVAL_SECS}"
    )))
    .unwrap();
    assert_eq!(
        at_cap.debug_memory_interval,
        Some(Duration::from_secs(MAX_INTERVAL_SECS))
    );
    assert_eq!(
        at_cap.counter_interval,
        Some(Duration::from_secs(MAX_INTERVAL_SECS))
    );
}

#[test]
fn two_file_reflectors_cannot_share_a_folded_name() {
    // Table keys differing only in case or surrounding whitespace resolve to one display name;
    // reject rather than silently produce two reflectors sharing it (env-vs-file already folds).
    let cfg = |k1: &str, k2: &str| {
        format!(
            r#"
                [reflectors.{k1}]
                source_if = "a"
                target_if = "b"
                mdns = true
                [reflectors.{k2}]
                source_if = "c"
                target_if = "d"
                mdns = true
                "#
        )
    };
    assert!(matches!(
        from_toml(&cfg("TV", "tv")),
        Err(ConfigError::DuplicateReflectorName { name }) if name.as_str() == "tv"
    ));
    assert!(matches!(
        from_toml(&cfg("\"  tv  \"", "tv")),
        Err(ConfigError::DuplicateReflectorName { name }) if name.as_str() == "tv"
    ));
}

#[test]
#[cfg_attr(miri, ignore = "opens a real file")]
fn read_config_file_tolerates_a_non_utf8_path() {
    use std::os::unix::ffi::OsStrExt;
    // An invalid-UTF-8 path byte must not panic; a missing file yields ReadFile (rendered lossily).
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/no/\xff/such.toml"));
    assert!(matches!(
        read_config_file(path),
        Err(ConfigError::ReadFile { .. })
    ));
}

#[test]
fn old_debug_memory_bool_is_rejected() {
    // The 0.10.x `debug_memory = true` no longer parses (renamed to an interval, and the config
    // denies unknown fields). The deliberate breaking change fails loud at startup rather than
    // silently ignoring a stale setting.
    let text = r#"
            debug_memory = true
            [reflectors.d]
            source_if = "a"
            target_if = "b"
            mdns = true
            "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn wol_defaults_to_ports_7_and_9() {
    let cfg = from_toml(
        r#"
            [reflectors.w]
            source_if = "a"
            target_if = "b"
            wol = true
            "#,
    )
    .unwrap();
    let ports: Vec<u16> = cfg.reflectors[0]
        .wol
        .as_ref()
        .unwrap()
        .ports
        .iter()
        .map(|p| p.get())
        .collect();
    assert_eq!(ports, [7, 9]);
}

#[test]
fn multiple_reflectors_parse() {
    let cfg = from_toml(
        r#"
            [reflectors.zebra]
            source_if = "a"
            target_if = "b"
            mdns = true

            [reflectors.alpha]
            source_if = "a"
            target_if = "c"
            mdns = true
            "#,
    )
    .unwrap();
    let mut names: Vec<&str> = cfg.reflectors.iter().map(|r| r.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["alpha", "zebra"]);
}

#[test]
fn empty_config_is_rejected() {
    assert!(matches!(err(""), ConfigError::NoReflectors));
}

#[test]
fn invalid_log_level() {
    let text = r#"
            log_level = "verbose"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn reflector_with_no_protocol() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
        "#;
    assert!(matches!(err(text), ConfigError::NoProtocol { name } if name.as_str() == "x"));
}

#[test]
fn source_and_target_must_differ() {
    let text = r#"
            [reflectors.x]
            source_if = "same"
            target_if = "same"
            mdns = true
        "#;
    assert!(
        matches!(err(text), ConfigError::SameInterface { value, .. } if value.as_str() == "same")
    );
}

#[test]
fn missing_source_if() {
    let text = r#"
            [reflectors.x]
            target_if = "b"
            mdns = true
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn empty_source_if() {
    let text = r#"
            [reflectors.x]
            source_if = ""
            target_if = "b"
            mdns = true
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn missing_target_if() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            mdns = true
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn empty_target_if() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = ""
            mdns = true
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn wol_ports_without_wol() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            wol_ports = [7]
        "#;
    assert!(matches!(err(text), ConfigError::WolPortsWithoutWol { .. }));
}

#[test]
fn dial_without_ssdp() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            dial = true
        "#;
    assert!(matches!(err(text), ConfigError::DialWithoutSsdp { .. }));
}

#[test]
fn dial_requires_ipv4() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            ssdp = true
            dial = true
            address_family = "ipv6"
        "#;
    assert!(matches!(err(text), ConfigError::DialRequiresIpv4 { .. }));
}

#[test]
fn wol_port_zero_rejected() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = [0]
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn duplicate_wol_port_rejected() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = [7, 7]
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn empty_wol_ports_rejected() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = []
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn wol_port_out_of_range_rejected() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = [70000]
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn invalid_mac() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            macs = ["zz:zz:zz:zz:zz:zz"]
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn invalid_address_family() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            address_family = "ipv5"
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn unknown_reflector_key_rejected() {
    let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            typo = true
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn unknown_top_level_key_rejected() {
    let text = r#"
            log_levle = "info"

            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn top_level_reflector_table_is_rejected() {
    // Reflectors must be nested under [reflectors.<name>], not top-level tables.
    let text = r#"
            [tv]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn empty_file_reflector_key_rejected() {
    let text = r#"
            [reflectors.""]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
    assert!(matches!(err(text), ConfigError::EmptyReflectorName { .. }));
}

#[test]
fn whitespace_file_reflector_key_rejected() {
    let text = r#"
            [reflectors."   "]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
    assert!(matches!(err(text), ConfigError::EmptyReflectorName { .. }));
}

#[test]
fn conflicting_mdns_reflectors_rejected() {
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Mdns,
            ..
        }
    ));
}

#[test]
fn conflicting_wsd_reflectors_rejected() {
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "cams"
            wsd = true

            [reflectors.b]
            source_if = "lan"
            target_if = "cams"
            wsd = true
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Wsd,
            ..
        }
    ));
}

#[test]
fn udp_relays_conflict_on_a_shared_port_and_destination() {
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003, 9004]
            udp_groups = ["239.255.90.90"]
            udp_broadcast = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9004]
            udp_groups = ["239.255.90.90"]
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Udp,
            ..
        }
    ));
}

#[test]
fn udp_relays_on_one_port_with_disjoint_destinations_coexist() {
    let cfg = from_toml(
        r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003]
            udp_broadcast = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003]
            udp_groups = ["239.255.90.90"]
            "#,
    )
    .unwrap();
    assert_eq!(cfg.reflectors.len(), 2);
}

#[test]
fn udp_relay_on_a_protocols_group_conflicts_with_it() {
    // The relay on 5353 would carry mDNS a second time; the conflict names mDNS.
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [5353]
            udp_groups = ["224.0.0.251"]
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Mdns,
            ..
        }
    ));
}

#[test]
fn udp_relay_on_a_protocols_group_conflicts_either_way_round() {
    // mDNS relays responses iot -> lan whatever the entry's direction.
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "iot"
            target_if = "lan"
            udp_ports = [5353]
            udp_groups = ["224.0.0.251"]
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Mdns,
            ..
        }
    ));
}

#[test]
fn macs_never_separate_a_discovery_protocol_from_a_udp_relay() {
    // Queries from any client are relayed regardless of `macs`.
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [5353]
            udp_groups = ["224.0.0.251"]
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Mdns,
            ..
        }
    ));
}

#[test]
fn udp_relay_on_a_wol_port_in_the_other_direction_coexists() {
    // Wake-on-LAN relays source -> target only.
    let cfg = from_toml(
        r#"
            [reflectors.wake]
            source_if = "lan"
            target_if = "iot"
            wol = true

            [reflectors.relay]
            source_if = "iot"
            target_if = "lan"
            udp_ports = [9]
            udp_broadcast = true
            "#,
    )
    .unwrap();
    assert_eq!(cfg.reflectors.len(), 2);
}

#[test]
fn udp_relay_off_a_protocols_groups_coexists_with_it() {
    let cfg = from_toml(
        r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [5353]
            udp_broadcast = true
            "#,
    )
    .unwrap();
    assert_eq!(cfg.reflectors.len(), 2);
}

#[test]
fn udp_relay_on_a_wol_port_conflicts_in_a_family_wol_uses() {
    let text = r#"
            [reflectors.wake]
            source_if = "lan"
            target_if = "iot"
            wol = true

            [reflectors.relay]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9]
            udp_broadcast = true
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Wol,
            ..
        }
    ));
    // An IPv4-only WoL entry never relays a v6 magic packet.
    let cfg = from_toml(
        r#"
            [reflectors.wake]
            source_if = "lan"
            target_if = "iot"
            address_family = "ipv4"
            wol = true

            [reflectors.relay]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9]
            udp_groups = ["ff02::1"]
            "#,
    )
    .unwrap();
    assert_eq!(cfg.reflectors.len(), 2);
}

#[test]
fn different_protocols_on_one_port_coexist() {
    // WoL admits only magic packets and SSDP only its own messages, so port 1900 shared
    // between them relays nothing twice.
    let cfg = from_toml(
        r#"
            [reflectors.wake]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [1900]

            [reflectors.discovery]
            source_if = "lan"
            target_if = "iot"
            ssdp = true
            "#,
    )
    .unwrap();
    assert_eq!(cfg.reflectors.len(), 2);
}

#[test]
fn udp_relays_on_disjoint_ports_coexist() {
    let cfg = from_toml(
        r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003]
            udp_broadcast = true

            [reflectors.squeezebox]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [3483]
            udp_broadcast = true
            "#,
    )
    .unwrap();
    assert_eq!(cfg.reflectors.len(), 2);
}

#[test]
fn bidirectional_conflicts_with_the_reverse_entry() {
    // a relays both ways, so b's iot->lan leg duplicates a's second leg.
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            bidirectional = true

            [reflectors.b]
            source_if = "iot"
            target_if = "lan"
            mdns = true
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Mdns,
            ..
        }
    ));
}

#[test]
fn bidirectional_entries_on_different_pairs_do_not_conflict() {
    let cfg = from_toml(
        r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            bidirectional = true

            [reflectors.b]
            source_if = "lan"
            target_if = "guest"
            mdns = true
            bidirectional = true
            "#,
    )
    .unwrap();
    assert_eq!(cfg.reflectors.len(), 2);
}

#[test]
fn reverse_direction_does_not_conflict() {
    // lan->iot and iot->lan reflect opposite directions; not a duplicate.
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "iot"
            target_if = "lan"
            mdns = true
        "#;
    assert!(from_toml(text).is_ok());
}

#[test]
fn different_protocols_do_not_conflict() {
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            wol = true
        "#;
    assert!(from_toml(text).is_ok());
}

#[test]
fn distinct_macs_do_not_conflict() {
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:02"]
        "#;
    assert!(from_toml(text).is_ok());
}

#[test]
fn omitted_macs_conflicts_with_any() {
    // An absent MAC filter matches any device, so it overlaps a specific one.
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Mdns,
            ..
        }
    ));
}

#[test]
fn macs_list_parses() {
    let cfg = from_toml(
        r#"
            [reflectors.tv]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01", "00:00:00:00:00:02"]
            "#,
    )
    .unwrap();
    let macs = cfg.reflectors[0].macs.as_ref().unwrap();
    assert_eq!(macs.len(), 2);
    assert!(macs.contains(&"00:00:00:00:00:01".parse().unwrap()));
    assert!(macs.contains(&"00:00:00:00:00:02".parse().unwrap()));
}

#[test]
fn legacy_mac_field_is_now_unknown() {
    // `mac` was replaced by `macs` in 0.9.0; deny_unknown_fields rejects the old key.
    let text = r#"
            [reflectors.tv]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            mac = "02:42:ac:11:00:09"
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn empty_macs_list_rejected() {
    let text = r#"
            [reflectors.tv]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = []
        "#;
    assert!(matches!(err(text), ConfigError::Parse(_)));
}

#[test]
fn overlapping_macs_sets_conflict() {
    // The two allow-sets share 00:..:02, so both would reflect that device's mDNS.
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01", "00:00:00:00:00:02"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:02", "00:00:00:00:00:03"]
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Mdns,
            ..
        }
    ));
}

#[test]
fn disjoint_macs_sets_do_not_conflict() {
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01", "00:00:00:00:00:02"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:03", "00:00:00:00:00:04"]
        "#;
    assert!(from_toml(text).is_ok());
}

#[test]
fn disjoint_address_families_do_not_conflict() {
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            address_family = "ipv4"

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            address_family = "ipv6"
        "#;
    assert!(from_toml(text).is_ok());
}

#[test]
fn overlapping_wol_ports_conflict() {
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [7, 9]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [9, 4000]
        "#;
    assert!(matches!(
        err(text),
        ConfigError::ConflictingReflectors {
            protocol: Protocol::Wol,
            ..
        }
    ));
}

#[test]
fn disjoint_wol_ports_do_not_conflict() {
    let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [7, 9]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [4000]
        "#;
    assert!(from_toml(text).is_ok());
}
