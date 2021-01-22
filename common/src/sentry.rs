// Copyright (c) 2018-2021 The MobileCoin Foundation

use sentry as sentry_core;
use std::env;

pub use sentry_core::configure_scope;

pub fn init() -> Option<sentry_core::internals::ClientInitGuard> {
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

            let guard = sentry::init(sentry::ClientOptions {
                attach_stacktrace: true,
                dsn: dsn.parse().ok(),
                environment: Some(branch.into()),
                ..Default::default()
            });

            sentry_core::integrations::panic::register_panic_handler();

            sentry_core::configure_scope(|scope| {
                // Add our GIT commit to each message.
                scope.set_tag("git_commit", mc_util_build_info::git_commit());

                // Add current thread name to each message.
                scope.add_event_processor(Box::new(move |mut event| {
                    event.extra.insert(
                        "thread".into(),
                        std::thread::current().name().unwrap_or("?").into(),
                    );
                    Some(event)
                }));
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
