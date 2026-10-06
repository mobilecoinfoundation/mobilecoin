// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helper module for setting up logging to Sentry

use std::env;

pub use sentry::configure_scope;

/// Initialize Sentry logging.
pub fn init() -> Option<sentry::ClientInitGuard> {
    // See if we have the two required environment variables for configuring Sentry.
    let dsn = env::var("MC_SENTRY_DSN")
        .ok()
        .filter(|val| !val.trim().is_empty());
    let branch = env::var("MC_BRANCH")
        .ok()
        .filter(|val| !val.trim().is_empty());

    match (dsn, branch) {
        // We have everything we need to init Sentry.
        (Some(dsn), Some(branch)) => {
            if branch.contains('/') {
                panic!("MC_BRANCH cannot contain '/'");
            }

            let mut options = sentry::ClientOptions::default();
            options.attach_stacktrace = true;
            options.dsn = dsn.parse().ok();
            options.default_integrations = true;
            options.environment = Some(branch.into());
            let guard = sentry::init(sentry::apply_defaults(options));

            sentry::configure_scope(|scope| {
                // Add our GIT commit to each message.
                scope.set_tag("git_commit", mc_util_build_info::git_commit());
            });

            Some(guard)
        }

        // Only DSN but no branch - this is invalid configuration.
        (Some(_dsn), None) => {
            panic!("Cannot enable sentry (MC_SENTRY_DSN) without branch (MC_BRANCH)");
        }

        // No DSN, don't care about branch.
        _ => None,
    }
}
