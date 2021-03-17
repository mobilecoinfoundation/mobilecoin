// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains a cargo invoker

use crate::{
    env::Environment,
    vars::{
        ENV_CARGO_BUILD_DEP_INFO_BASEDIR, ENV_CARGO_BUILD_JOBS, ENV_CARGO_BUILD_PIPELINING,
        ENV_CARGO_BUILD_TARGET, ENV_CARGO_CACHE_RUSTC_INFO, ENV_CARGO_HOME, ENV_CARGO_HTTP_CAINFO,
        ENV_CARGO_HTTP_CHECK_REVOKE, ENV_CARGO_HTTP_DEBUG, ENV_CARGO_HTTP_LOW_SPEED_LIMIT,
        ENV_CARGO_HTTP_MULTIPLEXING, ENV_CARGO_HTTP_SSL_VERSION, ENV_CARGO_HTTP_USER_AGENT,
        ENV_CARGO_INCREMENTAL, ENV_CARGO_NET_GIT_FETCH_WITH_CLI, ENV_CARGO_NET_OFFLINE,
        ENV_CARGO_NET_RETRY, ENV_CARGO_TARGET_DIR, ENV_CARGO_TERM_COLOR, ENV_CARGO_TERM_VERBOSE,
        ENV_HTTPS_PROXY, ENV_HTTP_TIMEOUT, ENV_RUSTC, ENV_RUSTC_WRAPPER, ENV_RUSTDOC,
        ENV_RUSTDOCFLAGS, ENV_RUSTFLAGS, ENV_TERM,
    },
};
use std::{
    collections::HashMap,
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use url::Url;

/// A helper method to clear and/or inject new values into a command's
/// environment
fn str_env(command: &mut Command, clean_env: bool, value: Option<&impl AsRef<OsStr>>, env: &str) {
    if clean_env || value.is_some() {
        command.env_remove(env);
    }

    if let Some(v) = value {
        command.env(env, v);
    }
}

/// A helper method to clear and/or inject a separated array of strings into the
/// given command's environment
fn strv_env(command: &mut Command, clean_env: bool, values: &[String], env: &str, sep: &str) {
    if clean_env || !values.is_empty() {
        command.env_remove(env);
    }

    if values.is_empty() {
        str_env(command, clean_env, None as Option<&String>, env);
    } else {
        let v = values.join(sep);
        str_env(command, clean_env, Some(&v), env);
    }
}

/// A helper method to clear and/or inject an optional boolean value as a "0" or
/// "1" into the given command's environment
fn onezero_env(command: &mut Command, clean_env: bool, value: Option<bool>, env: &str) {
    if clean_env || value.is_some() {
        command.env_remove(env);
    }

    if let Some(val) = value {
        let v = val as u8;
        str_env(command, clean_env, Some(&v.to_string()), env);
    }
}

/// A helper method to clear and/or injected an optional duration value as
/// seconds into the given command's environment
fn duration_env(command: &mut Command, clean_env: bool, value: Option<&Duration>, env: &str) {
    if clean_env || value.is_some() {
        command.env_remove(env);
    }

    if let Some(val) = value {
        str_env(command, clean_env, Some(&val.as_secs().to_string()), env);
    }
}

/// A helper method to clear and/or injected an optional integer value into the
/// given command's environment
fn u64_env(command: &mut Command, clean_env: bool, value: Option<&u64>, env: &str) {
    if clean_env || value.is_some() {
        command.env_remove(env);
    }

    if let Some(val) = value {
        str_env(command, clean_env, Some(&val.to_string()), env);
    }
}

/// A builder-pattern which constructs a command to invoke cargo build
#[derive(Clone, Debug)]
pub struct CargoBuilder {
    working_dir: PathBuf,
    clean_env: bool,
    cargo_path: PathBuf,

    home: Option<PathBuf>,
    target_dir: Option<PathBuf>,
    rustc: Option<PathBuf>,
    rustc_wrapper: Option<PathBuf>,
    rustdoc: Option<PathBuf>,
    rustdocflags: Vec<String>,
    rustflags: Vec<String>,
    incremental: Option<bool>,
    cache_rustc_info: Option<bool>,
    term: Option<String>,

    build_jobs: Option<u64>,
    target: Option<String>,
    dep_info_basedir: Option<PathBuf>,
    pipelining: Option<bool>,

    http_debug: Option<bool>,
    http_proxy: Option<String>,
    http_timeout: Option<Duration>,
    http_cainfo: Option<PathBuf>,
    http_check_revoke: Option<bool>,
    http_ssl_version: Option<String>,
    http_low_speed_limit: Option<u64>,
    http_multiplexing: Option<bool>,
    http_user_agent: Option<String>,
    net_retry: Option<u64>,
    net_git_fetch_with_cli: Option<bool>,
    net_offline: Option<bool>,
    registries: HashMap<String, Url>,
    term_verbose: Option<bool>,
    term_color: Option<bool>,

    profile: String,
    locked: bool,

    emit_rerun_if_changed: bool,
}

impl CargoBuilder {
    /// Construct a new builder instance to run cargo in the given directory.
    ///
    /// If clean_env is set, cargo configuration variables will not be passed
    /// through from the command.
    pub fn new(env: &Environment, working_dir: &Path, clean_env: bool) -> Self {
        let cargo_path = env.cargo().to_owned();
        let profile = env.profile().to_owned();
        Self {
            working_dir: working_dir.to_owned(),
            clean_env,
            cargo_path,
            home: None,
            target_dir: None,
            rustc: None,
            rustc_wrapper: None,
            rustdoc: None,
            rustdocflags: Vec::default(),
            rustflags: Vec::default(),
            incremental: None,
            cache_rustc_info: None,
            term: None,
            build_jobs: None,
            target: None,
            dep_info_basedir: None,
            pipelining: None,
            http_debug: None,
            http_proxy: None,
            http_timeout: None,
            http_cainfo: None,
            http_check_revoke: None,
            http_ssl_version: None,
            http_low_speed_limit: None,
            http_multiplexing: None,
            http_user_agent: None,
            net_retry: None,
            net_git_fetch_with_cli: None,
            net_offline: None,
            registries: HashMap::default(),
            term_verbose: None,
            term_color: None,
            profile,
            locked: env.locked(),
            emit_rerun_if_changed: true,
        }
    }

    /// Constructs the command which will execute cargo
    pub fn construct(&mut self) -> Command {
        let mut command = Command::new(&self.cargo_path);

        command.current_dir(&self.working_dir);

        // Environment variables Cargo reads

        str_env(
            &mut command,
            self.clean_env,
            self.home.as_ref(),
            ENV_CARGO_HOME,
        );
        str_env(
            &mut command,
            self.clean_env,
            self.target_dir.as_ref(),
            ENV_CARGO_TARGET_DIR,
        );
        str_env(&mut command, self.clean_env, self.rustc.as_ref(), ENV_RUSTC);
        str_env(
            &mut command,
            self.clean_env,
            self.rustc_wrapper.as_ref(),
            ENV_RUSTC_WRAPPER,
        );
        str_env(
            &mut command,
            self.clean_env,
            self.rustdoc.as_ref(),
            ENV_RUSTDOC,
        );
        strv_env(
            &mut command,
            self.clean_env,
            &self.rustdocflags,
            ENV_RUSTDOCFLAGS,
            " ",
        );
        strv_env(
            &mut command,
            self.clean_env,
            &self.rustflags,
            ENV_RUSTFLAGS,
            " ",
        );
        onezero_env(
            &mut command,
            self.clean_env,
            self.incremental,
            ENV_CARGO_INCREMENTAL,
        );
        onezero_env(
            &mut command,
            self.clean_env,
            self.cache_rustc_info,
            ENV_CARGO_CACHE_RUSTC_INFO,
        );

        str_env(
            &mut command,
            self.clean_env,
            self.http_proxy.as_ref(),
            ENV_HTTPS_PROXY,
        );
        duration_env(
            &mut command,
            self.clean_env,
            self.http_timeout.as_ref(),
            ENV_HTTP_TIMEOUT,
        );
        str_env(&mut command, self.clean_env, self.term.as_ref(), ENV_TERM);

        // Configuration environment variables

        u64_env(
            &mut command,
            self.clean_env,
            self.build_jobs.as_ref(),
            ENV_CARGO_BUILD_JOBS,
        );
        str_env(
            &mut command,
            self.clean_env,
            self.target.as_ref(),
            ENV_CARGO_BUILD_TARGET,
        );
        str_env(
            &mut command,
            self.clean_env,
            self.dep_info_basedir.as_ref(),
            ENV_CARGO_BUILD_DEP_INFO_BASEDIR,
        );
        onezero_env(
            &mut command,
            self.clean_env,
            self.pipelining,
            ENV_CARGO_BUILD_PIPELINING,
        );

        onezero_env(
            &mut command,
            self.clean_env,
            self.http_debug,
            ENV_CARGO_HTTP_DEBUG,
        );
        str_env(
            &mut command,
            self.clean_env,
            self.http_cainfo.as_ref(),
            ENV_CARGO_HTTP_CAINFO,
        );
        onezero_env(
            &mut command,
            self.clean_env,
            self.http_check_revoke,
            ENV_CARGO_HTTP_CHECK_REVOKE,
        );
        str_env(
            &mut command,
            self.clean_env,
            self.http_ssl_version.as_ref(),
            ENV_CARGO_HTTP_SSL_VERSION,
        );
        u64_env(
            &mut command,
            self.clean_env,
            self.http_low_speed_limit.as_ref(),
            ENV_CARGO_HTTP_LOW_SPEED_LIMIT,
        );
        onezero_env(
            &mut command,
            self.clean_env,
            self.http_multiplexing,
            ENV_CARGO_HTTP_MULTIPLEXING,
        );
        str_env(
            &mut command,
            self.clean_env,
            self.http_user_agent.as_ref(),
            ENV_CARGO_HTTP_USER_AGENT,
        );
        u64_env(
            &mut command,
            self.clean_env,
            self.net_retry.as_ref(),
            ENV_CARGO_NET_RETRY,
        );
        onezero_env(
            &mut command,
            self.clean_env,
            self.net_git_fetch_with_cli,
            ENV_CARGO_NET_GIT_FETCH_WITH_CLI,
        );
        onezero_env(
            &mut command,
            self.clean_env,
            self.net_offline,
            ENV_CARGO_NET_OFFLINE,
        );

        // Note, we don't remove any other registries which are part of the env here
        for (name, index) in self.registries.iter() {
            str_env(
                &mut command,
                self.clean_env,
                Some(&index.as_str()),
                &format!(
                    "CARGO_REGISTRY_{}_INDEX",
                    name.to_ascii_uppercase().replace('-', "_")
                ),
            );
        }

        onezero_env(
            &mut command,
            self.clean_env,
            self.term_verbose,
            ENV_CARGO_TERM_VERBOSE,
        );
        onezero_env(
            &mut command,
            self.clean_env,
            self.term_color,
            ENV_CARGO_TERM_COLOR,
        );

        command.arg("build").arg("-vv");

        if self.profile == "release" {
            command.arg("--release");
        }

        if self.locked {
            command.arg("--locked");
        }

        command
    }

    /// Set the path to the cargo executable
    pub fn cargo_path(&mut self, cargo: &Path) -> &mut Self {
        self.cargo_path = cargo.to_owned();
        self
    }

    /// Set the CARGO_HOME variable for invoking cargo
    pub fn home(&mut self, home: &Path) -> &mut Self {
        self.home = Some(home.to_owned());
        self
    }

    /// Set the CARGO_TARGET_DIR variable for invoking cargo
    pub fn target_dir(&mut self, target_dir: &Path) -> &mut Self {
        self.target_dir = Some(target_dir.to_owned());
        self
    }

    /// Set the RUSTC variable for invoking cargo
    pub fn rustc(&mut self, rustc: &Path) -> &mut Self {
        self.rustc = Some(rustc.to_owned());
        self
    }

    /// Set the RUSTC_WRAPPER variable for invoking cargo
    pub fn rustc_wrapper(&mut self, rustc_wrapper: &Path) -> &mut Self {
        self.rustc_wrapper = Some(rustc_wrapper.to_owned());
        self
    }

    /// Set the RUSTDOC variable when invoking cargo
    pub fn rustdoc(&mut self, rustdoc: &Path) -> &mut Self {
        self.rustdoc = Some(rustdoc.to_owned());
        self
    }

    /// Add an item to the RUSTDOCFLAGS environment string
    pub fn add_rustdoc_flag(&mut self, rustdoc_flag: &str) -> &mut Self {
        self.rustdocflags.push(rustdoc_flag.to_owned());
        self
    }

    /// Add multiple items to the RUSTDOCFLAGS environment string
    pub fn add_rustdoc_flags(&mut self, rustdoc_flags: &[&str]) -> &mut Self {
        for flag in rustdoc_flags {
            self.rustdocflags.push((*flag).to_owned());
        }
        self
    }

    /// Add an item to the RUSTFLAGS environment string
    pub fn add_rust_flag(&mut self, rust_flag: &str) -> &mut Self {
        self.rustflags.push(rust_flag.to_owned());
        self
    }

    /// Add multiple items to the RUSTFLAGS environment string
    pub fn add_rust_flags(&mut self, rust_flags: &[&str]) -> &mut Self {
        for flag in rust_flags {
            self.rustflags.push((*flag).to_owned());
        }
        self
    }

    /// Explicitly set whether incremental builds are enabled or disabled
    pub fn incremental(&mut self, incremental: bool) -> &mut Self {
        self.incremental = Some(incremental);
        self
    }

    /// Enable/disable whether or not cargo should cache rust info
    pub fn cache_rustc_info(&mut self, cache_rustc_info: bool) -> &mut Self {
        self.cache_rustc_info = Some(cache_rustc_info);
        self
    }

    /// Set the terminal environment variable.
    pub fn term(&mut self, term: &str) -> &mut Self {
        self.term = Some(term.to_owned());
        self
    }

    /// Override the `build.jobs` configuration option
    pub fn build_jobs(&mut self, build_jobs: u64) -> &mut Self {
        self.build_jobs = Some(build_jobs);
        self
    }

    /// Override the `build.target` configuration option
    pub fn target(&mut self, target: &str) -> &mut Self {
        self.target = Some(target.to_owned());
        self
    }

    /// Override the `build.dep-info-basedir` configuration option
    pub fn dep_info_basedir(&mut self, dep_info_basedir: &Path) -> &mut Self {
        self.dep_info_basedir = Some(dep_info_basedir.to_owned());
        self
    }

    /// Override the `build.pipelining` configuration option
    pub fn pipelining(&mut self, pipelining: bool) -> &mut Self {
        self.pipelining = Some(pipelining);
        self
    }

    /// Override the `http.debug` configuration option
    pub fn http_debug(&mut self, http_debug: bool) -> &mut Self {
        self.http_debug = Some(http_debug);
        self
    }

    /// Override the `http.proxy` configuration option
    pub fn http_proxy(&mut self, http_proxy: &str) -> &mut Self {
        self.http_proxy = Some(http_proxy.to_owned());
        self
    }

    /// Override the `http.debug` configuration option
    pub fn http_timeout(&mut self, http_timeout: Duration) -> &mut Self {
        self.http_timeout = Some(http_timeout);
        self
    }

    /// Override the `http.cainfo` file configuration option
    pub fn http_cainfo(&mut self, http_cainfo: &Path) -> &mut Self {
        self.http_cainfo = Some(http_cainfo.to_owned());
        self
    }

    /// Override the `http.check-revoke` configuration option
    pub fn http_check_revoke(&mut self, http_check_revoke: bool) -> &mut Self {
        self.http_check_revoke = Some(http_check_revoke);
        self
    }

    /// Override the `http.ssl-version` configuration option
    pub fn http_ssl_version(&mut self, http_ssl_version: &str) -> &mut Self {
        self.http_ssl_version = Some(http_ssl_version.to_owned());
        self
    }

    /// Override the `http.low-speed-limit` configuration option
    pub fn http_low_speed_limit(&mut self, http_low_speed_limit: u64) -> &mut Self {
        self.http_low_speed_limit = Some(http_low_speed_limit);
        self
    }

    /// Override the `http.multiplexing` configuration option
    pub fn http_multiplexing(&mut self, http_multiplexing: bool) -> &mut Self {
        self.http_multiplexing = Some(http_multiplexing);
        self
    }

    /// Override the `http.user-agent` configuration option
    pub fn http_user_agent(&mut self, http_user_agent: String) -> &mut Self {
        self.http_user_agent = Some(http_user_agent);
        self
    }

    /// Override the `net.retry` configuration option
    pub fn net_retry(&mut self, net_retry: u64) -> &mut Self {
        self.net_retry = Some(net_retry);
        self
    }

    /// Override the `net.get_fetch_with_cli` configuration option
    pub fn net_git_fetch_with_cli(&mut self, net_git_fetch_with_cli: bool) -> &mut Self {
        self.net_git_fetch_with_cli = Some(net_git_fetch_with_cli);
        self
    }

    /// Override the `net.offline` configuration option
    pub fn net_offline(&mut self, net_offline: bool) -> &mut Self {
        self.net_offline = Some(net_offline);
        self
    }

    /// Add a new crates.io-style registry to this invocation of cargo
    pub fn add_registry(&mut self, name: String, index: Url) -> &mut Self {
        self.registries.insert(name, index);
        self
    }

    /// Sets whether to use verbose stdout in the cargo run
    pub fn term_verbose(&mut self, term_verbose: bool) -> &mut Self {
        self.term_verbose = Some(term_verbose);
        self
    }

    /// Sets whether to output terminal colors
    pub fn term_color(&mut self, term_color: bool) -> &mut Self {
        self.term_color = Some(term_color);
        self
    }

    /// Override the inherited profile (i.e. `--release`)
    pub fn profile(&mut self, profile: String) -> &mut Self {
        self.profile = profile;
        self
    }

    /// Override the inherited locked argument (i.e. `--locked`)
    pub fn locked(&mut self, locked: bool) -> &mut Self {
        self.locked = locked;
        self
    }
}
