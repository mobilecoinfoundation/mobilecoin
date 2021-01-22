// Copyright (c) 2018-2021 The MobileCoin Foundation

#![feature(proc_macro_diagnostic)]

extern crate proc_macro;

mod error;

use self::error::{DiagnosticError, Result};
use proc_macro::TokenStream;
use quote::quote;
use syn::parse_quote;

#[proc_macro_attribute]
pub fn test_with_logger(_attr: TokenStream, item: TokenStream) -> TokenStream {
    match test_with_logger_impl(item.clone()) {
        Ok(tokens) => tokens,
        Err(e) => {
            e.emit();
            item
        }
    }
}

fn test_with_logger_impl(item: TokenStream) -> Result<TokenStream> {
    let mut original_fn: syn::ItemFn = match syn::parse(item) {
        Ok(ast) => ast,
        Err(e) => {
            let diag = proc_macro2::Span::call_site()
                .unstable()
                .error("lru_cache may only be used on functions");
            return Err(DiagnosticError::new_with_syn_error(diag, e));
        }
    };

    let orig_ident = original_fn.ident.clone();
    let orig_name = original_fn.ident.to_string();

    let new_name = format!("__wrapped_{}", original_fn.ident.to_string());
    original_fn.ident = syn::Ident::new(&new_name[..], original_fn.ident.span());
    let new_ident = original_fn.ident.clone();

    let mut new_fn: syn::ItemFn = parse_quote! {
        #[test]
        fn #orig_ident() {
            let test_name = format!("{}::{}", module_path!(), #orig_name);
            let logger = mc_common::logger::create_test_logger(test_name);
            mc_common::logger::slog_scope::scope(
                &logger.clone(),
                || {
                    #new_ident(logger);
                }
            );
        }
    };
    new_fn.attrs.extend(original_fn.attrs.clone());
    original_fn.attrs = Vec::new();

    let out = quote! {
        #new_fn
        #original_fn

    };
    Ok(out.into())
}

#[proc_macro_attribute]
pub fn bench_with_logger(_attr: TokenStream, item: TokenStream) -> TokenStream {
    match bench_with_logger_impl(item.clone()) {
        Ok(tokens) => tokens,
        Err(e) => {
            e.emit();
            item
        }
    }
}

fn bench_with_logger_impl(item: TokenStream) -> Result<TokenStream> {
    let mut original_fn: syn::ItemFn = match syn::parse(item) {
        Ok(ast) => ast,
        Err(e) => {
            let diag = proc_macro2::Span::call_site()
                .unstable()
                .error("lru_cache may only be used on functions");
            return Err(DiagnosticError::new_with_syn_error(diag, e));
        }
    };

    let orig_ident = original_fn.ident.clone();
    let orig_name = original_fn.ident.to_string();

    let new_name = format!("__wrapped_{}", original_fn.ident.to_string());
    original_fn.ident = syn::Ident::new(&new_name[..], original_fn.ident.span());
    let new_ident = original_fn.ident.clone();

    let mut new_fn: syn::ItemFn = parse_quote! {
        #[bench]
        fn #orig_ident(b: &mut Bencher) {
            let bench_name = format!("{}::{}", module_path!(), #orig_name);
            let logger = mc_common::logger::create_test_logger(bench_name);
            mc_common::logger::slog_scope::scope(
                &logger.clone(),
                || {
                    #new_ident(logger, b);
                }
            );
        }
    };
    new_fn.attrs.extend(original_fn.attrs.clone());
    original_fn.attrs = Vec::new();

    let out = quote! {
        #new_fn
        #original_fn

    };
    Ok(out.into())
}
