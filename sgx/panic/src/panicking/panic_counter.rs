// Copyright (c) 2018-2021 The MobileCoin Foundation

// To detect when the panic process is failing, we have a thread-local counter
//
// The following function encapsulates modifying this counter and returning
// the resulting value.
//
// This is meant to be equivalent to `update_panic_count` from rust std
// `panicking.rs` module.
//
// Unfortunately, the `thread_local!` macro is part of std, so we can't quite
// use the same implementation that std does, since we are `no_std`.
//
// I believe that this implementation is also correct.
// See also rust issue tracking stabilization of [thread_local]
// https://github.com/rust-lang/rust/issues/29594

pub fn update_panic_count(change: isize) -> usize {
    #[thread_local]
    static mut COUNT: usize = 0;

    // Note(chbeck): It seems to me that this should not be `unsafe` as there
    // is no race here, but I guess that thread_local, being only an attribute,
    // cannot change the language rules around `static mut` variable.
    unsafe {
        COUNT = (COUNT as isize + change) as usize;
        COUNT
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn update_panic_count0() {
        assert_eq!(0, update_panic_count(0));
        assert_eq!(1, update_panic_count(1));
        assert_eq!(1, update_panic_count(0));
        assert_eq!(0, update_panic_count(-1));
        assert_eq!(0, update_panic_count(0));
        assert_eq!(1, update_panic_count(1));
        assert_eq!(1, update_panic_count(0));
        assert_eq!(2, update_panic_count(1));
        assert_eq!(2, update_panic_count(0));
        assert_eq!(0, update_panic_count(-2));
    }
}
