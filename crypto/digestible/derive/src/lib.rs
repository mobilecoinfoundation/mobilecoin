// Copyright (c) 2018-2020 MobileCoin Inc.

// The `quote!` macro requires deep recursion.
#![recursion_limit = "4096"]

extern crate alloc;
extern crate proc_macro;

use quote::{format_ident, quote};

use proc_macro::TokenStream;
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Fields, FieldsNamed, FieldsUnnamed, Generics, Ident,
};

fn try_digestible(input: TokenStream) -> Result<TokenStream, &'static str> {
    let input: DeriveInput = syn::parse(input).unwrap();

    let ident = input.ident;
    let generics = &input.generics;
    match input.data {
        Data::Struct(variant_data) => try_digestible_struct(&ident, generics, &variant_data),
        Data::Enum(variant_data) => try_digestible_enum(&ident, generics, &variant_data),
        Data::Union(..) => Err("Digestible can not be derived for a union"),
    }
}

fn try_digestible_struct(
    ident: &Ident,
    generics: &Generics,
    variant_data: &DataStruct,
) -> Result<TokenStream, &'static str> {
    // fields is a Vec<syn::Field> (I think)
    let fields = match &variant_data.fields {
        Fields::Named(FieldsNamed { named: fields, .. })
        | Fields::Unnamed(FieldsUnnamed {
            unnamed: fields, ..
        }) => fields.into_iter().collect(),
        Fields::Unit => Vec::new(),
    };

    // call is a Vec<TokenStream> (I think)
    let call = fields
        .into_iter()
        .enumerate()
        .map(|(idx, field)| {
            match &field.ident {
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
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics mc_crypto_digestible::Digestible for #ident #ty_generics #where_clause {
            fn digest<D: mc_crypto_digestible::Digest>(&self, hasher: &mut D) {
                hasher.input(stringify!(#ident).as_bytes());
                hasher.input(stringify!(#impl_generics).as_bytes());
                #(#call)*
            }
        }
    };
    Ok(expanded.into())
}

fn try_digestible_enum(
    ident: &Ident,
    generics: &Generics,
    variant_data: &DataEnum,
) -> Result<TokenStream, &'static str> {
    let call = variant_data
        .variants
        .iter()
        .enumerate()
        .map(|(idx, variant)| {
            let variant_ident = &variant.ident;

            // Our behavior differs based on whether the enum variant is a unit (has no data
            // associated with it), or named (has sruct data associated with it), or unnamed (has
            // tuple data assocated with it).
            match &variant.fields {
                // For an enum variant that doesn't have associated data (e.g. SomeEnum::MyVariant)
                // we generate code that looks like this:
                // Self::MyVariant => {
                //   hasher.input(&(0 as u64).to_le_bytes()); // This is the variant's index.
                //   hasher.input("MyVariant").as_bytes());
                // }
                Fields::Unit => {
                    quote! {
                        Self::#variant_ident => {
                            hasher.input(&(#idx as u64).to_le_bytes());
                            hasher.input(stringify!(#variant_ident).as_bytes());
                        },
                    }
                }

                // For an enum variant that has anonymous fields (e.g. SomeEnum::MyVariant(u32,
                // u64)) we generate code that looks like this:
                // Self::MyVariant(field_0, field_1) => {
                //   hasher.input(&(0 as u64).to_le_bytes()); // This is the variant's index.
                //   hasher.input("MyVariant").as_bytes());
                //   hasher.input("0").as_bytes());
                //   field_0.digest(hasher);
                //   hasher.input("1").as_bytes());
                //   field_1.digest(hasher);
                // }
                Fields::Unnamed(FieldsUnnamed {
                    unnamed: fields, ..
                }) => {
                    let field_idents = fields
                        .iter()
                        .enumerate()
                        .map(|(idx, _field)| format_ident!("field_{}", idx))
                        .collect::<Vec<_>>();

                    let per_field_digest = fields
                        .iter()
                        .enumerate()
                        .map(|(idx, _field)| {
                            let index = syn::Index::from(idx);
                            let field_ident = format_ident!("field_{}", idx);
                            quote! {
                                hasher.input(stringify!(#index).as_bytes());
                                #field_ident.digest(hasher);
                            }
                        })
                        .collect::<Vec<_>>();

                    quote! {
                        Self::#variant_ident(#(#field_idents),*) => {
                            hasher.input(&(#idx as u64).to_le_bytes());
                            hasher.input(stringify!(#variant_ident).as_bytes());
                            #(#per_field_digest)*
                        }
                    }
                }

                // For an enum variant that has anonymous fields (e.g. SomeEnum::MyVariant { a: u64, b: u64 }
                // we generate code that looks like this:
                // Self::MyVariant { a, b } => {
                //   hasher.input(&(0 as u64).to_le_bytes()); // This is the variant's index.
                //   hasher.input("MyVariant").as_bytes());
                //   hasher.input("a").as_bytes());
                //   a.digest(hasher);
                //   hasher.input("b").as_bytes());
                //   b.digest(hasher);
                // }
                Fields::Named(FieldsNamed { named: fields, .. }) => {
                    let field_idents = fields.iter().map(|field| &field.ident).collect::<Vec<_>>();

                    let per_field_digest = fields
                        .iter()
                        .map(|field| {
                            let field_ident = &field.ident;
                            quote! {
                                hasher.input(stringify!(#field_ident).as_bytes());
                                #field_ident.digest(hasher);
                            }
                        })
                        .collect::<Vec<_>>();

                    quote! {
                        Self::#variant_ident { #(#field_idents),* } => {
                            hasher.input(&(#idx as u64).to_le_bytes());
                            hasher.input(stringify!(#variant_ident).as_bytes());
                            #(#per_field_digest)*
                        }
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics mc_crypto_digestible::Digestible for #ident #ty_generics #where_clause {
            fn digest<D: mc_crypto_digestible::Digest>(&self, hasher: &mut D) {
                // Hash the name of the enum and generic specializations.
                hasher.input(stringify!(#ident).as_bytes());
                hasher.input(stringify!(#impl_generics).as_bytes());

                // Per-variant hashing.
                match self {
                    #(#call)*
                }
            }
        }
    };

    Ok(expanded.into())
}

#[proc_macro_derive(Digestible)]
pub fn digestible(input: TokenStream) -> TokenStream {
    try_digestible(input).unwrap()
}
