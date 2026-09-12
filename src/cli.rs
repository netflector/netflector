//! Command-line parsing, hand-rolled: one positional and four flags don't justify a dependency
//! on an embedded target.

use std::ffi::OsString;
use std::path::Path;

use crate::error::UsageError;

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Invocation<'a> {
    Run {
        path: Option<&'a Path>,
        join_groups: bool,
    },
    CheckConfig(Option<&'a Path>),
    Help,
    Version,
}

/// Parse `args` (`argv[0]` already stripped). `--help` and `--version` win over anything after
/// them; an unknown option before them still errors. A second positional is refused rather than
/// ignored, since a second path is far more likely a typo than an intent. `--` ends option
/// parsing, so a config path that starts with a dash stays reachable.
///
/// # Errors
/// [`UsageError`] for an unknown option or a second positional.
pub(crate) fn parse(args: &[OsString]) -> Result<Invocation<'_>, UsageError> {
    let mut check = false;
    let mut join_groups = true;
    let mut path: Option<&Path> = None;
    let mut options_done = false;

    for arg in args {
        if !options_done {
            if arg == "--" {
                options_done = true;
                continue;
            }
            if arg == "-h" || arg == "--help" {
                return Ok(Invocation::Help);
            }
            if arg == "-V" || arg == "--version" {
                return Ok(Invocation::Version);
            }
            if arg == "--check-config" {
                check = true;
                continue;
            }
            if arg == "--no-join" {
                join_groups = false;
                continue;
            }
        }
        // A lone "-" stays a path (stdin by convention).
        let text = arg.to_string_lossy();
        if !options_done && text.starts_with('-') && text != "-" {
            return Err(UsageError::UnknownOption(text.into_owned()));
        }
        if path.is_some() {
            return Err(UsageError::TooManyArgs(text.into_owned()));
        }
        path = Some(Path::new(arg));
    }

    Ok(if check {
        Invocation::CheckConfig(path)
    } else {
        Invocation::Run { path, join_groups }
    })
}

/// Ends with a newline; print with `print!`.
pub(crate) const HELP: &str = concat!(
    "netflector ",
    env!("CARGO_PKG_VERSION"),
    "

Reflects link-local service traffic (Wake-on-LAN, mDNS, SSDP, WS-Discovery, DIAL) between
two network interfaces.

usage: netflector [--check-config] [--no-join] [--] [CONFIG]

  CONFIG           TOML config file. NETFLECTOR_* environment variables are merged on top of
                   it. Omit it to configure from the environment alone. Put `--` first if the
                   file name begins with a dash.

  --check-config   Load and validate the configuration, then exit. It parses only: no
                   interface is opened, so it needs no privileges and it cannot tell you that
                   an interface is missing or unreachable.
  --no-join        Do not join multicast groups. Group traffic then reaches netflector only
                   where the link delivers it without a membership, as an emulated or
                   promiscuous fabric does.
  -V, --version    Print the version and exit.
  -h, --help       Print this help and exit.
"
);

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn run(path: Option<&str>) -> Invocation<'_> {
        Invocation::Run {
            path: path.map(Path::new),
            join_groups: true,
        }
    }

    #[test]
    fn no_args_runs_from_the_environment() {
        assert_eq!(parse(&[]).unwrap(), run(None));
    }

    #[test]
    fn no_join_clears_the_group_joins() {
        let a = args(&["--no-join", "netflector.toml"]);
        assert_eq!(
            parse(&a).unwrap(),
            Invocation::Run {
                path: Some(Path::new("netflector.toml")),
                join_groups: false,
            }
        );
    }

    #[test]
    fn a_lone_positional_is_the_config_path() {
        let a = args(&["netflector.toml"]);
        assert_eq!(parse(&a).unwrap(), run(Some("netflector.toml")));
    }

    #[test]
    fn check_config_takes_the_same_optional_path() {
        let a = args(&["--check-config"]);
        assert_eq!(parse(&a).unwrap(), Invocation::CheckConfig(None));
        let b = args(&["--check-config", "netflector.toml"]);
        assert_eq!(
            parse(&b).unwrap(),
            Invocation::CheckConfig(Some(Path::new("netflector.toml")))
        );
        // The flag may follow the path as readily as precede it.
        let c = args(&["netflector.toml", "--check-config"]);
        assert_eq!(
            parse(&c).unwrap(),
            Invocation::CheckConfig(Some(Path::new("netflector.toml")))
        );
    }

    #[test]
    fn help_and_version_win_over_the_rest_of_the_line() {
        for flag in ["-h", "--help"] {
            let a = args(&[flag, "netflector.toml", "--nonsense"]);
            assert_eq!(parse(&a).unwrap(), Invocation::Help);
        }
        for flag in ["-V", "--version"] {
            let a = args(&[flag, "--nonsense"]);
            assert_eq!(parse(&a).unwrap(), Invocation::Version);
        }
    }

    #[test]
    fn a_second_positional_is_rejected_not_ignored() {
        let a = args(&["netflector.toml", "extra"]);
        assert!(matches!(parse(&a), Err(UsageError::TooManyArgs(arg)) if arg == "extra"));
    }

    #[test]
    fn an_unknown_option_is_rejected() {
        let a = args(&["--check-cfg"]);
        assert!(matches!(parse(&a), Err(UsageError::UnknownOption(opt)) if opt == "--check-cfg"));
    }

    #[test]
    fn a_lone_dash_is_a_path_not_an_option() {
        let a = args(&["-"]);
        assert_eq!(parse(&a).unwrap(), run(Some("-")));
    }

    #[test]
    fn dash_dash_reaches_a_config_whose_name_looks_like_an_option() {
        // Without the separator these paths are unreachable: every leading-dash argument would be
        // read as an option, a known one or an error.
        let a = args(&["--", "--check-config"]);
        assert_eq!(parse(&a).unwrap(), run(Some("--check-config")));
        let b = args(&["--", "--nonsense"]);
        assert_eq!(parse(&b).unwrap(), run(Some("--nonsense")));
    }

    #[test]
    fn dash_dash_ends_option_parsing_for_good() {
        // The flag before the separator still applies; the one after it is just a file name.
        let a = args(&["--check-config", "--", "--help"]);
        assert_eq!(
            parse(&a).unwrap(),
            Invocation::CheckConfig(Some(Path::new("--help")))
        );
        // A second positional after the separator is still a second positional.
        let b = args(&["--", "one", "two"]);
        assert!(matches!(parse(&b), Err(UsageError::TooManyArgs(arg)) if arg == "two"));
    }

    #[test]
    fn help_names_every_flag_it_accepts() {
        // The help is the only place the flags are documented, so a flag the parser takes but the
        // help omits is a bug the user pays for.
        for flag in [
            "--check-config",
            "--no-join",
            "--version",
            "-V",
            "--help",
            "-h",
        ] {
            assert!(HELP.contains(flag), "help does not mention {flag}");
        }
        // The separator needs its own check: a bare "--" is a substring of every long flag, so
        // asserting HELP.contains("--") would pass even if "--" went undocumented. Pin the usage
        // line instead, which is where it has to appear to be of any use.
        assert!(HELP.contains("[--]"), "help does not show the -- separator");
    }
}
