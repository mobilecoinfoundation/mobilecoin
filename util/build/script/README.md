Cargo build-script assistance, from MobileCoin.

This crate provides a programatic API for dealing with the various strings passed into build scripts via environment variables. The primary interface of use is the `Environment` structure:

```no_run
use mc_util_build_script::Environment;

let env = Environment::new().expect("Could not parse environment");
assert_eq!(env.name(), "mc_util_build_script");
```
