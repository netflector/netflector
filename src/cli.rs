//! Command-line parsing.
//!
//! Hand-rolled rather than pulled from a crate: the whole surface is one optional
//! positional and three flags, and the binary ships to embedded ARM.

use std::ffi::OsString;
use std::path::Path;

use crate::error::UsageError;

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Invocation<'a> {
    /// Run netflector, configured from the given file (if any) plus `NETFLECTOR_*`.
    Run(Option<&'a Path>),
    /// Load and validate that same configuration, then exit.
    CheckConfig(Option<&'a Path>),
    Help,
    Version,
}

/// Parse `args` (with `argv[0]` already stripped).
///
/// `--help` and `--version` win over everything else, so they answer even when the rest of the
/// line is nonsense. Otherwise netflector takes at most one positional; extras are rejected
/// rather than ignored, since a second path is far more likely a typo than an intent.
///
/// `--` ends option parsing, so a config file whose name begins with a dash is still reachable
/// (`netflector -- --check-config` reads a file called `--check-config`). Without it such a path
/// would be unreachable, since every leading-dash argument is otherwise read as an option.
///
/// # Errors
/// [`UsageError`] for an unknown option or a second positional argument.
pub(crate) fn parse(args: &[OsString]) -> Result<Invocation<'_>, UsageError> {
    let mut check = false;
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
        }
        // A lone "-" stays a path (some callers mean stdin by it); anything else that leads with a
        // dash is an option we do not know, and guessing at it would be worse than saying so.
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
        Invocation::Run(path)
    })
}

/// `--help` text. Ends with a newline; print it with `print!`.
pub(crate) const HELP: &str = concat!(
    "netflector ",
    env!("CARGO_PKG_VERSION"),
    "

Reflects link-local service traffic (Wake-on-LAN, mDNS, SSDP, WS-Discovery, DIAL) between
two network interfaces.

usage: netflector [--check-config] [--] [CONFIG]

  CONFIG           TOML config file. NETFLECTOR_* environment variables are merged on top of
                   it. Omit it to configure from the environment alone. Put `--` first if the
                   file name begins with a dash.

  --check-config   Load and validate the configuration, then exit. It parses only: no
                   interface is opened, so it needs no privileges and it cannot tell you that
                   an interface is missing or unreachable.
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

    #[test]
    fn no_args_runs_from_the_environment() {
        assert_eq!(parse(&[]).unwrap(), Invocation::Run(None));
    }

    #[test]
    fn a_lone_positional_is_the_config_path() {
        let a = args(&["netflector.toml"]);
        assert_eq!(
            parse(&a).unwrap(),
            Invocation::Run(Some(Path::new("netflector.toml")))
        );
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
        assert_eq!(parse(&a).unwrap(), Invocation::Run(Some(Path::new("-"))));
    }

    #[test]
    fn dash_dash_reaches_a_config_whose_name_looks_like_an_option() {
        // Without the separator these paths are unreachable: every leading-dash argument would be
        // read as an option, a known one or an error.
        let a = args(&["--", "--check-config"]);
        assert_eq!(
            parse(&a).unwrap(),
            Invocation::Run(Some(Path::new("--check-config")))
        );
        let b = args(&["--", "--nonsense"]);
        assert_eq!(
            parse(&b).unwrap(),
            Invocation::Run(Some(Path::new("--nonsense")))
        );
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
        for flag in ["--check-config", "--version", "-V", "--help", "-h"] {
            assert!(HELP.contains(flag), "help does not mention {flag}");
        }
        // The separator needs its own check: a bare "--" is a substring of every long flag, so
        // asserting HELP.contains("--") would pass even if "--" went undocumented. Pin the usage
        // line instead, which is where it has to appear to be of any use.
        assert!(HELP.contains("[--]"), "help does not show the -- separator");
    }
}
