// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Install a signal handler for SIGCHILD that kills this process if the child
//! dies
use arrayvec::ArrayString;
use core::{
    fmt::Write,
    sync::atomic::{AtomicBool, Ordering},
};
use libc::{_exit, c_void, write, STDOUT_FILENO};
use nix::{
    sys::{
        signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, SIGCHLD},
        wait::waitpid,
    },
    unistd::Pid,
};

static mut EXIT_ON_SIGCHLD_FLAG: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_sigchld(_: libc::c_int) {
    print_signal_safe("[main] Got SIGCHLD!\n");
    if unsafe { EXIT_ON_SIGCHLD_FLAG.load(Ordering::SeqCst) } {
        print_signal_safe("[main] Child exited unexpectedly, this is fatal\n");
        exit_signal_safe(1);
    }

    // Reap the child
    if let Err(err) = waitpid(Pid::from_raw(-1), None) {
        let mut buf = ArrayString::<[u8; 512]>::new();
        writeln!(
            &mut buf,
            "[main] waitpid() failed, could not reap child: {}",
            err
        )
        .expect("Could not write");
        print_signal_safe(&buf);
    }
}

fn print_signal_safe(s: &str) {
    unsafe {
        write(STDOUT_FILENO, s.as_ptr() as *const c_void, s.len());
    }
}

fn exit_signal_safe(status: i32) {
    unsafe {
        _exit(status);
    }
}

/// Set up the SIGCHLD handler. Call this once when your process starts.
pub fn setup_handler() {
    // Set up SIGCHLD handler
    let sig_action = SigAction::new(
        SigHandler::Handler(handle_sigchld),
        SaFlags::empty(),
        SigSet::empty(),
    );
    if let Err(err) = unsafe { sigaction(SIGCHLD, &sig_action) } {
        panic!("[main] sigaction() failed: {}", err);
    };
}

/// Whether we should halt on receiving SIGCHLD
///
/// While the test is happening, we should treat the child crashing as fatal,
/// so set this true before spawning the child process.
/// Set it false just before killing the child.
pub fn exit_on_sigchld(value: bool) {
    unsafe {
        EXIT_ON_SIGCHLD_FLAG.store(value, Ordering::SeqCst);
    }
}
