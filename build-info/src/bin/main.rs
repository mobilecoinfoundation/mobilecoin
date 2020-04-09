// Copyright (c) 2018-2020 MobileCoin Inc.

//! Output the build_info that we compiled with
//! This is in order to validate the build / any caching mechanisms

use std::env;

fn usage() {
    eprintln!("Usage: show-build-info [--git-commit] [--profile] [--debug] [--all]");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() <= 1 {
        usage();
    }
    if args.len() > 1 {
        if args[1] == "--git-commit" {
            print!("{}", build_info::GIT_COMMIT);
            return;
        } else if args[1] == "--profile" {
            print!("{}", build_info::PROFILE);
            return;
        } else if args[1] == "--debug" {
            print!("{}", build_info::DEBUG);
            return;
        } else if args[1] == "--all" {
            let mut result = String::new();
            build_info::write_report(&mut result).unwrap();
            print!("{}", result);
            return;
        }
    }
    usage();
}
