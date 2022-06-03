# Introduction

Thanks for looking into how to help with MobileCoin! We're under active development, so please read through the document(s) below to learn more!

## Get In Touch

* [Ask usage questions and chat on our Discord](https://discord.gg/mobilecoin).
* [Report bugs or ask for features on Github](https://github.com/mobilecoinfoundation/mobilecoin/issues).
* [Design protocol enhancements or large changes via an MCIP](https://github.com/mobilecoinfoundation/mcips).
* [Ask us about participating in testnet](mailto:testnet@mobilecoin.com)!

## Helping with code

If you want to start developing with MobileCoin, it's pretty easy to get started:

* Fork the MobileCoin repository to your own github account:
```bash
$ gh repo fork mobilecoinfoundation/mobilecoin
```
* Install Docker on your machine
* Use our provided scripts to start the mobilecoin builder image
```bash
$ ./mob prompt
```
* Find an issue marked as a "[good first issue](https://github.com/mobilecoinfoundation/mobilecoin/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)", and comment that you'd like to take it (we'll assign it to your github account)
* Create a branch for your feature
```bash
$ git checkout -b issue-1234
```
* Work on the feature
* Commit your changes
```bash
$ git commit -am "Fixes #1234"
```
* Push your changes to your repository
```bash
$ git push
```
* Create a pull request:
```bash
$ gh pr create --project "Blockchain Core"
```
* Nobody likes CLAs, but you will need to sign [our CLA](./CLA.md) before your pull request can be merged. Please email [cla@mobilecoin.com](mailto://cla@mobilecoin.com) and we will send you a copy.

If you'd prefer to run build natively on Ubuntu LTS, you can use the `init_debian.sh` and `install_sgx.sh` scripts to setup your environment, but please be aware that CI will run on the docker image, so it's worth keeping it around to test.

# Coding Style

Part of submitting a PR to the MobileCoin Foundation is ensuring that the formatting is correct.

## Automated Checks

The easiest part of ensuring the style guide is followed is running the following utilities, which are checked for every PR:

 * `rustfmt`: Reformats the code according to the top-level `rustfmt.toml`. If the repo is "dirty" after this has been run, the PR cannot be merged.
 * `cargo clippy`: An in-depth checking utility that will look for code which the authors (The Rust Foundation) think are not idiomatic rust. In practice this is a lot like PEP-8

## Rust's Style Guide

The Rust Foundation has a [WIP style guide](https://doc.rust-lang.org/1.0.0/style/style/README.html), and we should follow it's recommendations unless there's a good reason not to:

* [Avoid `use *`, except in tests](https://doc.rust-lang.org/1.0.0/style/style/imports.html#avoid-use-*,-except-in-tests.)
* [Prefer fully importing types/traits while module-qualifying functions](https://doc.rust-lang.org/1.0.0/style/style/imports.html#prefer-fully-importing-types/traits-while-module-qualifying-functions.)
* [Always separately bind RAII (lock) guards](https://doc.rust-lang.org/1.0.0/style/features/let.html#always-separately-bind-raii-guards.-[fixme:-needs-rfc]) -- Note that you should use brace scopes.

## MobileCoin's Style Guide

In addition (and sometimes overrulling) the Rust Style Guide, we have our own rules:

### Sort your inputs

The Rust Style Guide asks developers to [sort their inputs](https://doc.rust-lang.org/1.0.0/style/style/imports.html), but in this situation the sorting is considered sub-optimal. We would prefer to sort our inputs in a similar, but distinct manner:

* `extern crate` directives (typically this is just `extern crate alloc;` in no-std crates)
* `pub use` (re-)exports
* `pub mod` exports
* `mod` definitions
* `use` imports

This ordering, when combined with our [`rustfmt` configuration](rustfmt.toml) will sort each group appropriately.

For example:

```rust
extern crate alloc;

pub use crate::{
    module::TypeToExport,
};
pub use dependency::TypeWereUsing;

mod module;

use dependency::SomeTypeWeUseOurselves;
```

### Re-export types when necessary

Before re-exporting types, consider is whether there is an advantage to be gained by creating a newtype wrapper, e.g.:

```rust
/// This is meant to restrict the types of math which can performed on a block
/// height (to eliminate off-by-one errors).
pub struct BlockHeight(NotZero64);

/// A way to implement serde on ExternalNonSerdeThing for others
pub struct SerdeThing(ExternalNonSerdeThing);

impl Serialize for SerdeThing { /* ... */ }
impl DeserializeOwned for SerdeThing { /* ... */ }
```

If there _is_ such an advantage, then it's usually better to wrap the types. If there isn't an advantage, then you should re-export any types you're using (or expecting your users to use).

Don't:

```rust
use other_crate::ExternalThing;

pub fn my_function(thing: ExternalThing) -> bool {
    /* ... */
}
```

Do:

```rust
pub use other_crate::ExternalThing;

pub fn my_function(thing: ExternalThing) -> bool {
    /* ... */
}
```

### Export types at the crate level

The Rust Style Guide contains the admonition to [Reexport the most important types at the crate level](https://doc.rust-lang.org/1.0.0/style/style/organization.html#reexport-the-most-important-types-at-the-crate-level.). We should take this a step beyond, and simply re-export *all* publicly visible types at the crate level.

Don't:

```rust
pub use crate::module::SomeType;

mod module {
    pub struct SomeType;

    // Users will have to access this using `thecrate::module::Error`?
    pub enum Error {
        Error1,
        Error2,
    }

    enum Strategy {
        Strat1(SomeType),
        Strat2,
    }
}
```

Do:

```rust
pub use crate::module::{SomeType, Error as SomeError};

mod module {
    pub struct SomeType;
    pub enum Error {
        Error1,
        Error2,
    }

    enum Strategy {
        Strat1(SomeType),
        Strat2,
    }
}
```

### Use public modules to group functions

This is the flip side of the Rust style guide's admonition to [prefer fully importing types/traits while module-qualifying functions](https://doc.rust-lang.org/1.0.0/style/style/imports.html#prefer-fully-importing-types/traits-while-module-qualifying-functions.) and our own admonition to [export types at the crate level](#export-types-at-the-crate-level).

Types should only be exported at the top level, but if you have lots of related bare functions, consider grouping them into modules exposed via a `pub mod`.

Don't:

```rust
pub struct SomeType;

pub fn foonary_frobnicate() -> bool {
    /* ... */
}

pub fn foonary_widgify() -> SomeType {
    /* ... */
}
```

Don't:

```rust
mod foonary {
    pub struct SomeType;

    pub fn frobnicate() -> SomeType {
        /* ... */
    }

    pub fn widgify() -> SomeType {
        /* ... */
    }
}

pub use crate::foonary::{
    SomeType,
    frobnicate as foonary_frobnicate,
    widgify as foonary_widgify,
};
```

Do:

```rust
pub use crate::foonary::SomeType;

pub mod foonary {
    pub(crate) struct SomeType;

    pub fn frobnicate() -> SomeType {
        /* ... */
    }

    pub fn widgify() -> SomeType {
        /* ... */
    }
}
```

### Avoid Manual Drops

Don't use `core::drop()`. There are exceptions to every rule, but you should always look to use an inner scope instead of `core::drop()`.
