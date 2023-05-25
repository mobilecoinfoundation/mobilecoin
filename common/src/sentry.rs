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

            let guard = sentry::init(sentry::apply_defaults(sentry::ClientOptions {
                attach_stacktrace: true,
                dsn: dsn.parse().ok(),
                default_integrations: true,
                environment: Some(branch.into()),
                ..Default::default()
            }));

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
