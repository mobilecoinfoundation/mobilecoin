// Copyright (c) 2018-2021 The MobileCoin Foundation

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
            print!("{}", mc_util_build_info::git_commit());
            return;
        } else if args[1] == "--profile" {
            print!("{}", mc_util_build_info::profile());
            return;
        } else if args[1] == "--debug" {
            print!("{}", mc_util_build_info::debug());
            return;
        } else if args[1] == "--all" {
            let mut result = String::new();
            mc_util_build_info::write_report(&mut result).unwrap();
            print!("{}", result);
            return;
        }
    }
    usage();
}
