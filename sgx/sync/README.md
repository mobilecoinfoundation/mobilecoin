mc-sgx-sync
========

The goal of this crate is to provide synchronization primitives, such as
mutexes, that work in sgx.

This is largely extracted from rust-sgx-sdk `sgx_tstd` lib.

We have only extracted the parts that we actually need to use. If it turns out
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
