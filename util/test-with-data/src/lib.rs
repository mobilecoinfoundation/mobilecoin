// Copyright (c) 2018-2022 The MobileCoin Foundation

#![feature(proc_macro_diagnostic)]

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Expr, ItemFn};

/// Attribute macro that wraps a function taking a single argument with
/// a test that uses the specified expression as the data source,
/// and calls the wrapped function with each of those cases.
///
/// The wrapped function must take a single argument, optionally by reference.
///
/// The data source can be any iterable whose items can be converted into
/// the argument type of the wrapped function, including arrays and Vec.
///
/// Here's a very simple example:
/// ```rust
/// # use mc_util_test_with_data::test_with_data;
///
/// #[test_with_data([1, 2, 3])]
/// fn silly(x: i32) {
///     assert!(x < 3);  // Fails on the third iteration.
/// }
/// ```
///
/// This macro is roughly equivalent to writing a test that calls
/// the following function:
///
/// ```rust
/// # #![feature(associated_type_bounds)]
///
/// fn with_data<T, I, F>(source: I, test: F)
/// where
///     I: Iterator<Item: Into<T>>,
///     F: Fn(T) -> (),
/// {
///     for case in source {
///         test(case.into());
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn test_with_data(attr: TokenStream, item: TokenStream) -> TokenStream {
    let function = syn::parse_macro_input!(item as ItemFn);
    let source = syn::parse_macro_input!(attr as Expr);
    test_with_data_impl(function, &source).into()
}

pub(crate) fn test_with_data_impl(mut orig_fn: ItemFn, source: &Expr) -> TokenStream2 {
    let inputs = &orig_fn.sig.inputs;
    if inputs.len() != 1 {
        return syn::Error::new_spanned(
            orig_fn.sig,
            "test_with_data only accepts functions that take one argument",
        )
        .into_compile_error();
    }

    // Rename the input fn, reusing the original name for the wrapper.
    let orig_ident = orig_fn.sig.ident;
    let wrapped_ident = quote::format_ident!("__check_{}", orig_ident);
    orig_fn.sig.ident = wrapped_ident.clone();

    // Handle arguments taken by reference.
    let arg_type = match inputs.first() {
        Some(syn::FnArg::Typed(syn::PatType { ty, .. })) => Some(ty.as_ref()),
        _ => None,
    };
    let (ref_token, _type) = match arg_type {
        Some(syn::Type::Reference(type_ref)) => (quote!(&), Some(type_ref.elem.as_ref())),
        _ => (TokenStream2::new(), arg_type),
    };

    // Define the wrapper.
    let mut new_fn: ItemFn = syn::parse_quote! {
        #[test]
        fn #orig_ident() {
            let cases = #source;
            for case in cases {
                #wrapped_ident(#ref_token case.into());
            }
        }
    };
    // Move other attributes to the new method.
    new_fn.attrs.append(&mut orig_fn.attrs);

    // Tag the wrapped function with cfg(test) so it is omitted in other
    // configurations.
    quote! {
        #[cfg(test)]
        #orig_fn
        #new_fn
    }
}
