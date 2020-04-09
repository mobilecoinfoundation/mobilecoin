// Copyright (c) 2018-2020 MobileCoin Inc.

// The `quote!` macro requires deep recursion.
#![recursion_limit = "4096"]

extern crate alloc;
extern crate proc_macro;

use quote::quote;

use proc_macro::TokenStream;
use syn::{Data, DataStruct, DeriveInput, Fields, FieldsNamed, FieldsUnnamed};

fn try_digestible(input: TokenStream) -> Result<TokenStream, &'static str> {
    let input: DeriveInput = syn::parse(input).unwrap();

    let ident = input.ident;

    let variant_data = match input.data {
        Data::Struct(variant_data) => variant_data,
        Data::Enum(..) => return Err("Digestible can not be derived for an enum"),
        Data::Union(..) => return Err("Digestible can not be derived for a union"),
    };

    if !input.generics.params.is_empty() || input.generics.where_clause.is_some() {
        return Err("Digestible may not be derived for generic type (yet!)");
    }

    // fields is a Vec<syn::Field> (I think)
    let fields = match variant_data {
        DataStruct {
            fields: Fields::Named(FieldsNamed { named: fields, .. }),
            ..
        }
        | DataStruct {
            fields:
                Fields::Unnamed(FieldsUnnamed {
                    unnamed: fields, ..
                }),
            ..
        } => fields.into_iter().collect(),
        DataStruct {
            fields: Fields::Unit,
            ..
        } => Vec::new(),
    };

    // call is a Vec<TokenStream> (I think)
    let call = fields
        .into_iter()
        .enumerate()
        .map(|(idx, field)| {
            match field.ident {
                // this is a regular struct
                Some(field_ident) => {
                    quote! {
                        hasher.input(stringify!(#field_ident).as_bytes());
                        self.#field_ident.digest(hasher);
                    }
                }
                // this is a tuple struct, and the member doesn't have an identifier
                None => {
                    let index = syn::Index::from(idx);
                    quote! {
                        hasher.input(stringify!(#index).as_bytes());
                        self.#index.digest(hasher);
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    // Final expanded result
    let expanded = quote! {
        impl digestible::Digestible for #ident {
            fn digest<D: digestible::Digest>(&self, hasher: &mut D) {
                hasher.input(stringify!(#ident).as_bytes());
                #(#call)*
            }
        }
    };
    Ok(expanded.into())
}

#[proc_macro_derive(Digestible)]
pub fn digestible(input: TokenStream) -> TokenStream {
    try_digestible(input).unwrap()
}
