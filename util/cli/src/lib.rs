// Copyright (c) 2022 The MobileCoin Foundation

use clap::{CommandFactory, FromArgMatches, Parser};

/// Command line parser trait that provides build information into the version
/// string. In order to use this, one must pass in the `version` argument to the
/// `clap` attribute.  When the `version` flag is present it will be extended to
/// include the git commit of the crate.
pub trait ParserWithBuildInfo: Parser {
    /// Returns the `clap::Command` with the long version appended with the git
    /// commit information
    ///
    /// # Arguments
    ///
    /// * `build_info` - A String that will be populated with the build info
    ///   (git commit). This is passed in as it needs to live as long as the
    ///   `clap::Command`.
    fn command_with_build_info(build_info: &mut String) -> clap::Command {
        let mut command = <Self as CommandFactory>::command();
        if let Some(version) = command.get_version() {
            *build_info = format!(
                "{} commit: {}",
                version,
                mc_util_build_info::mobilecoin_git_commit()
            );
            command = command.long_version(&**build_info);
        }
        command
    }

    /// Similar to clap::Command::parse(), augmenting the version on the
    /// clap::Command with build information from [mc_util_build_info].
    fn parse() -> Self {
        let mut build_info = String::new();
        let command = Self::command_with_build_info(&mut build_info);
        let matches = command.get_matches();
        let res =
            <Self as FromArgMatches>::from_arg_matches(&matches).map_err(format_error::<Self>);
        match res {
            Ok(s) => s,
            Err(e) => e.exit(),
        }
    }
}

impl<T> ParserWithBuildInfo for T where T: Parser {}

fn format_error<T: CommandFactory>(err: clap::Error) -> clap::Error {
    let mut cmd = T::command();
    err.format(&mut cmd)
}

#[cfg(test)]
mod tests {
    use crate::ParserWithBuildInfo;

    #[test]
    fn version_on_clap_command() {
        #[derive(Clone, Debug, clap::Parser)]
        #[clap(version)]
        pub struct CommandWithVersion {}

        let mut info = String::new();
        let command = CommandWithVersion::command_with_build_info(&mut info);
        let expected_long_version = format!(
            "{} commit: {}",
            command.get_version().unwrap(),
            mc_util_build_info::mobilecoin_git_commit()
        );
        assert_eq!(command.get_long_version(), Some(&*expected_long_version));
    }
    #[test]
    fn no_version_on_clap_command() {
        #[derive(Clone, Debug, clap::Parser)]
        pub struct CommandWithoutVersion {}

        let mut info = String::new();
        let command = CommandWithoutVersion::command_with_build_info(&mut info);
        assert_eq!(command.get_long_version(), None);
    }
}
