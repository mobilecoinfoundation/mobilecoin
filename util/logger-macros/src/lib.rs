// Copyright (c) 2018-2021 The MobileCoin Foundation

#![feature(proc_macro_diagnostic)]

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

#[proc_macro_attribute]
pub fn test_with_logger(_attr: TokenStream, item: TokenStream) -> TokenStream {
    impl_with_logger(item, quote!(), quote!())
}

#[proc_macro_attribute]
pub fn bench_with_logger(_attr: TokenStream, item: TokenStream) -> TokenStream {
    impl_with_logger(item, quote!(b: &mut Bencher), quote!(,b))
}

fn impl_with_logger(item: TokenStream, params: TokenStream2, args: TokenStream2) -> TokenStream {
    let mut original_fn = syn::parse_macro_input!(item as syn::ItemFn);

    let orig_ident = original_fn.sig.ident.clone();
    let orig_name = orig_ident.to_string();

    let new_ident = quote::format_ident!("__wrapped_{}", orig_ident);
    original_fn.sig.ident = new_ident.clone();

    let mut new_fn: syn::ItemFn = syn::parse_quote! {
        #[test]
        fn #orig_ident(#params) {
            let test_name = format!("{}::{}", module_path!(), #orig_name);
            let logger = mc_common::logger::create_test_logger(test_name);
            mc_common::logger::slog_scope::scope(
                &logger.clone(),
                || #new_ident(logger #args)
            );
        }
    };
    // Move other attributes to the new method.
    new_fn.attrs.append(&mut original_fn.attrs);

    quote! {
        #new_fn
        #original_fn
    }
    .into()
}
