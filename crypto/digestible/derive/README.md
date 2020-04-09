digestible-derive
=================

This proc macro crate allows the use of `derive(Digestible)` in user structs.

The intended code gen is:

```
#[derive(Digestible)]
struct Foo {
    a: A,
    b: B,
    c: C
}
```

expands to something like:

```
impl Digestible for Foo {
    fn digest<D: Digest>(&self, hasher: &mut D) {
        hasher.input(b"a");
        self.a.digest(hasher);
        hasher.input(b"b");
        self.b.digest(hasher);
        hasher.input(b"c");
        self.c.digest(hasher);
    }
}
```

For comparison, the `derive(Hash)` stuff is implemented in `libsyntax_ext` in `rust/rust`,
however, that is implemented directly in the compiler and not in a proc_macro or even in libcore,
so we can't use the same code. Instead this is based most directly on the `prost-derive` crate.
