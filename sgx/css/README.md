Parse the `SIGSTRUCT` structure from [Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 3D: System Programming Guide, Part 4, Section 38.13](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf), as created by the `sgx_sign` SDK utility.

This crate exposes one primary API, the `Signature` structure, which can be loaded from bytes or a file, as needed.

# Examples

```ignore
use hex_fmt::HexFmt;
use std::path::Path;
use sgx_css::Signature;

fn main() {
    let path = Path::from("/path/to/cssfile");
    let sig = Signature::try_from(&path).expect("Could not parse SIGSTRUCT");
    println!("{}:{}", HexFmt(sig.mrenclave()), HexFmt(sig.mrsigner()));
}
```
