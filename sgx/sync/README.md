mc-sgx-sync
========

The goal of this crate is to provide synchronization primitives, such as
mutexes, that work in sgx.

This is largely extracted from rust-sgx-sdk `sgx_tstd` lib.

We have only extracted the parts that we actually need to use (and modified them
due to differences in how we expose parts of the `panicking`, in our version
this is exposed in `mc_sgx_panic` crate). If it turns out
we need more synchronization primitives we can go back and add them here.

- Mutex
- Condition Variable
- RwLock (similar to C++ shared_mutex)

Rationale
---------

In POSIX, mutexes are implemented in a system library called `libpthread`.
In linux, `libpthread` uses a kernel feature called `futex` "fast user-space mutex".

The memory underlying a futex exists in user-space, but the act of going to sleep
on a futex, and the act of waking threads that are sleeping on a particular futex,
both require a system call. So, standard mutexes cannot be used in sgx, because
sgx does not allow the use of system calls.

(Moreover, any linux synchronization primitive that wakes up threads or puts
them to sleep requires a system call, because the scheduler is not in user space
in linux, and this cannot be done without talking to the scheduler.)

Instead, intel provides an alternate implementation of mutexes for use in sgx,
and exposes C headers for this in the `sgx_tstdc` library. The code here is
rust wrappers around this intel-provided functionality. (Mostly derived from
https://github.com/baidu/rust-sgx-sdk)

Features
--------

This crate optionally depends on `mc_sgx_panic` but using it is recommended, and
this dependency is on by default.

Having access to `mc_sgx_panic` allows us to implement a "mutex poisoning" strategy
where if a thread panics and unwinds while holding a mutex, an atomic variable
adjacent to the mutex is incremented and any other threads waiting on the mutex
are woken up. They can then see that the mutex is poisoned and return an error
instead of locking the mutex. This allows those threads to avoid dead-locking
on the mutex that will never be released (because the memory it was protecting
is possibly corrupted by the thread that locked it and then panicked), and they
can proceed with some recovery strategy, or simply shutdown gracefully. So it
may permit a webserver to recover or fail gracefully in the event of a panic.

This functionality is only relevant in a `panic=unwind` configuration. If you
are doing `panic=abort`, then you can reasonably drop the dependency on
`mc_sgx_panic`, and in this case we will skip all the poisoning stuff, since it
will never be relevant.
