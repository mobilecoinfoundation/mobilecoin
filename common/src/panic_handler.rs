// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::logger;
use backtrace::Backtrace;
use std::{
    env,
    panic::{self, PanicInfo},
    process, thread, time,
};

/// Call this to ensure a process exits if a threads panics.
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicInfo<'_>| {
        handle_panic(pi);
    }));
}

fn handle_panic(panic_info: &PanicInfo<'_>) {
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());
    let thread_name = thread::current().name().unwrap_or("?").to_string();
    let process_name = env::args().next().unwrap_or_else(|| "?".to_string());

    // First, print the crash details.
    println!(
        "OH NO, WE CRASHED :( thread {} on {}",
        thread_name, process_name
    );
    println!("Details: {}", details);
    println!("{}", backtrace);

    // Also attempt to log using the logger.
    logger::global_log::crit!(
        "thread {} on {} panicked! {} {}",
        thread_name,
        process_name,
        details,
        backtrace,
    );

    // Give the logger, filebeat and sentry time to process the message.
    thread::sleep(time::Duration::from_millis(1000));

    // Kill the process. 13 is a random exit code to make it easier to tell a
    // process exited using this code flow.
    process::exit(13);
}
