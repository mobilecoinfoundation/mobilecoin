fog-ocall-oram-storage-untrusted
=============================

This crate provides the OCALL implementations for the fog-ocall-oram-storage
interface defined in the edl file.

These OCALL's define a way for the enclave to allocate, and later access,
memory that is managed by untrusted. The enclave is responsible to manage
the encryption and decryption of these blocks. The blocks are fixed-size and
this API is specifically meant to support ORAM.

Any implementation of this API is acceptable as long as it avoids memory corruption,
otherwise it just needs to go as fast as possible. Because this code is not in the
enclave, we can iterate on it without changing MRENCLAVE.

Details
-------

Each allocation consists of a data segment, and a metadata segment. They have
the same "count", but the data segment items are typically hundreds of times larger.

The current version works by allocating the data-segment using rust's analogue
of malloc: acquire memory without any specific initialization. This is because
the API has been arranged so that only the metadata segment needs to be zeroed
on first access. This avoids the need to initialize the vast majority of the memory,
which would be very slow.

One consequence of this is that the ORAM server's memory footprint will gradually
increase over time as it is running -- not all of the memory that it mallocs
will actually get mapped to physical memory at any point. We log the total amount
of memory that has been allocated in this manner.

Future directions
----------------

Future versions might try to bypass linux kernel paging,
use special hardware in some more sophisticated way, etc.

It may also be possible to move data into the enclave faster than we can with
Intel's buffer copying mechanism. For example, if the storage region in untrusted
is obtained using mmap or malloc, the enclave can likely copy directly from those
addresses into the trusted memory, and then check the mac values, and could skip
the whole ocall for checkin and checkout. This wouldn't be possible with storage
that doesn't get mapped into virtual memory, so it would be a specialized API.
