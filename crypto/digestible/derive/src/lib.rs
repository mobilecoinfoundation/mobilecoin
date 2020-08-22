// Copyright (c) 2018-2020 MobileCoin Inc.

// The `quote!` macro requires deep recursion.
#![recursion_limit = "4096"]

extern crate alloc;
extern crate proc_macro;

use quote::{format_ident, quote};

use core::convert::TryFrom;
use proc_macro::TokenStream;
use proc_macro2::Span;
use syn::{
    Attribute, Data, DataEnum, DataStruct, DeriveInput, Fields, FieldsNamed, FieldsUnnamed,
    Generics, Ident, Lit, Meta, NestedMeta,
};

/// These are configuration options that are selected by #[digestible(..)] attributes
/// at struct or enum declaration. They are parsed from the DeriveInput::attrs field.
#[derive(Default, Clone)]
struct AttributeConfig {
    /// Whether digestible should be derived "transparently", meaning,
    /// this is e.g. new-type wrapper around some other digestible type,
    /// and we should call through directly to the implementation on that type
    pub transparent: bool,
    /// Whether we should rename of the struct or enum, and use a user-provided
    /// string for the name, for purpose of hashing.
    /// This is a backwards compatibility tool.
    pub rename: Option<String>,
}

impl AttributeConfig {
    // Apply a nested meta item from syn to the current config state
    pub fn apply_meta(&mut self, nested_meta: &NestedMeta) -> Result<(), &'static str> {
        match nested_meta {
            NestedMeta::Lit(_) => {
                return Err("Unexpected digestible literal attribute");
            }
            NestedMeta::Meta(meta) => match meta {
                Meta::Path(path) => {
                    if path.is_ident("transparent") {
                        if !self.transparent {
                            self.transparent = true;
                        } else {
                            return Err("transparent cannot appear twice as an attribute");
                        }
                    } else {
                        return Err("unexpected digestible path attribute");
                    }
                }
                Meta::NameValue(mnv) => {
                    if mnv.path.is_ident("name") {
                        if self.rename.is_some() {
                            return Err("name = cannot appear twice in digestible attributes");
                        } else {
                            self.rename = match &mnv.lit {
                                Lit::Str(litstr) => Some(litstr.value()),
                                _ => {
                                    return Err("name = must be set to string literal in digestible attributes");
                                }
                            }
                        }
                    } else {
                        return Err("unexpected digestible feature attribute");
                    }
                }
                _ => {
                    return Err("unexpected digestible attribute");
                }
            },
        }
        Ok(())
    }
}

// Parse AttributeConfig from syn attribute list
impl TryFrom<&[Attribute]> for AttributeConfig {
    type Error = &'static str;

    fn try_from(src: &[Attribute]) -> Result<Self, &'static str> {
        let mut result = AttributeConfig::default();

        for attr in src {
            if attr.path.is_ident("digestible") {
                if let Meta::List(meta) = attr.parse_meta().unwrap() {
                    for meta_item in meta.nested.iter() {
                        result.apply_meta(meta_item)?;
                    }
                }
            }
        }

        if result.transparent && result.rename.is_some() {
            return Err("It is meaningless to combine digestible(transparent) and digestible(name=) features");
        }

        Ok(result)
    }
}

fn try_digestible(input: TokenStream) -> Result<TokenStream, &'static str> {
    let input: DeriveInput = syn::parse(input).unwrap();

    let ident = input.ident;
    let generics = &input.generics;
    let attr_config = AttributeConfig::try_from(&input.attrs[..])?;

    if attr_config.transparent {
        match input.data {
            Data::Struct(variant_data) => {
                try_digestible_struct_transparent(&ident, generics, &variant_data)
            }
            Data::Enum(_) => Err("Digestible cannot be derived transparently for an enum"),
            Data::Union(..) => Err("Digestible cannot be derived for a union"),
        }
    } else {
        // If the user specified a name, that's the custom name, otherwise use the ident
        let custom_name = if let Some(name) = attr_config.rename {
            Ident::new(name.as_ref(), Span::call_site())
        } else {
            ident.clone()
        };
        match input.data {
            Data::Struct(variant_data) => {
                try_digestible_struct(&ident, &custom_name, generics, &variant_data)
            }
            Data::Enum(variant_data) => {
                try_digestible_enum(&ident, &custom_name, generics, &variant_data)
            }
            Data::Union(..) => Err("Digestible cannot be derived for a union"),
        }
    }
}

fn try_digestible_struct(
    ident: &Ident,
    custom_name: &Ident,
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
    // this is the tokens representing, bringing the transcript to each field
    let call = fields
        .into_iter()
        .enumerate()
        .map(|(idx, field)| {
            match &field.ident {
                // this is a regular struct
                Some(field_ident) => {
                    quote! {
                        self.#field_ident.append_to_transcript_allow_omit(stringify!(#field_ident).as_bytes(), transcript);
                    }
                }
                // this is a tuple struct, and the member doesn't have an identifier
                None => {
                    let index = syn::Index::from(idx);
                    quote! {
                        self.#index.append_to_transcript_allow_omit(stringify!(#index).as_bytes(), transcript);
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    // Final expanded result
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics mc_crypto_digestible::Digestible for #ident #ty_generics #where_clause {
            fn append_to_transcript<DT: mc_crypto_digestible::DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                transcript.append_agg_header(context, stringify!(#custom_name).as_bytes());
                #(#call)*
                transcript.append_agg_closer(context, stringify!(#custom_name).as_bytes());
            }
        }
    };

    Ok(expanded.into())
}

fn try_digestible_struct_transparent(
    ident: &Ident,
    generics: &Generics,
    variant_data: &DataStruct,
) -> Result<TokenStream, &'static str> {
    let fields: Vec<&syn::Field> = match &variant_data.fields {
        Fields::Named(FieldsNamed { named: fields, .. })
        | Fields::Unnamed(FieldsUnnamed {
            unnamed: fields, ..
        }) => fields.into_iter().collect(),
        Fields::Unit => {
            return Err("digestible cannot be derived transparently for a unit struct");
        }
    };

    if fields.is_empty() {
        return Err("digestible cannot be derived transparently for a struct with no members");
    }
    if fields.len() > 1 {
        return Err("digestible cannot be derived transparently for a struct or tuple with more than one member");
    }

    // Final expanded result
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = if let Some(field_ident) = &fields[0].ident {
        quote! {
            impl #impl_generics mc_crypto_digestible::Digestible for #ident #ty_generics #where_clause {
                fn append_to_transcript<DT: mc_crypto_digestible::DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                    self.#field_ident.append_to_transcript(context, transcript);
                }
                fn append_to_transcript_allow_omit<DT: mc_crypto_digestible::DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                    self.#field_ident.append_to_transcript_allow_omit(context, transcript);
                }
            }
        }
    } else {
        quote! {
            impl #impl_generics mc_crypto_digestible::Digestible for #ident #ty_generics #where_clause {
                fn append_to_transcript<DT: mc_crypto_digestible::DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                    self.0.append_to_transcript(context, transcript);
                }
                fn append_to_transcript_allow_omit<DT: mc_crypto_digestible::DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                    self.0.append_to_transcript_allow_omit(context, transcript);
                }
            }
        }
    };

    Ok(expanded.into())
}

fn try_digestible_enum(
    ident: &Ident,
    custom_name: &Ident,
    generics: &Generics,
    variant_data: &DataEnum,
) -> Result<TokenStream, &'static str> {
    let call = variant_data
        .variants
        .iter()
        .enumerate()
        .map(|(which, variant)| {
            let variant_ident = &variant.ident;

            // Our behavior differs based on whether the enum variant is a unit (has no data
            // associated with it), or named (has sruct data associated with it), or unnamed (has
            // tuple data assocated with it).
            match &variant.fields {
                // For an enum variant that doesn't have associated data (e.g. SomeEnum::MyVariant)
                // we generate code that looks like this:
                // Self::MyVariant => {
                //   hasher.update(&(0 as u64).to_le_bytes()); // This is the variant's index.
                //   hasher.update("MyVariant").as_bytes());
                // }
                Fields::Unit => {
                    quote! {
                        Self::#variant_ident => {
                            transcript.append_var_header(context, stringify!(#custom_name).as_bytes(), #which as u32);
                            transcript.append_none(stringify!(#variant_ident).as_bytes());
                        },
                    }
                }

                // For an enum variant that has anonymous fields (e.g. SomeEnum::MyVariant(u32,
                // u64)) we generate code that looks like this:
                // Self::MyVariant(field_0, field_1) => {
                //   hasher.update(&(0 as u64).to_le_bytes()); // This is the variant's index.
                //   hasher.update("MyVariant").as_bytes());
                //   hasher.update("0").as_bytes());
                //   field_0.digest(hasher);
                //   hasher.update("1").as_bytes());
                //   field_1.digest(hasher);
                // }
                Fields::Unnamed(FieldsUnnamed {
                    unnamed: fields, ..
                }) => {
                    if fields.len() == 1 {
                        quote! {
                            Self::#variant_ident(val) => {
                                transcript.append_var_header(context, stringify!(#custom_name).as_bytes(), #which as u32);
                                val.append_to_transcript(stringify!(#variant_ident).as_bytes(), transcript);
                            }
                        }
                    } else {

                        let field_idents = fields
                             .iter()
                             .enumerate()
                             .map(|(idx, _field)| format_ident!("field_{}", idx))
                             .collect::<Vec<_>>();

                        // These are allow_omit, because they are appearing inside an aggregate (the anonymous struct)
                        let per_field_digest = fields
                             .iter()
                             .enumerate()
                             .map(|(idx, _field)| {
                                 let index = syn::Index::from(idx);
                                 let field_ident = format_ident!("field_{}", idx);
                                 quote! {
                                     #field_ident.append_to_transcript_allow_omit(stringify!(#index).as_bytes(), transcript);
                                 }
                             })
                             .collect::<Vec<_>>();

                        quote! {
                            Self::#variant_ident(#(#field_idents),* ) => {
                                transcript.append_var_header(context, stringify!(#custom_name).as_bytes(), #which as u32);
                                transcript.append_agg_header(stringify!(#variant_ident).as_bytes(), b"");
                                #(#per_field_digest)*;
                                transcript.append_agg_closer(stringify!(#variant_ident).as_bytes(), b"");
                            }
                        }
                    }
                }

                // For an enum variant that has named fields (e.g. SomeEnum::MyVariant { a: u64, b: u64 }
                // we generate code that looks like this:
                // Self::MyVariant { a, b } => {
                //   hasher.update(&(0 as u64).to_le_bytes()); // This is the variant's index.
                //   hasher.update("MyVariant").as_bytes());
                //   hasher.update("a").as_bytes());
                //   a.digest(hasher);
                //   hasher.update("b").as_bytes());
                //   b.digest(hasher);
                // }
                Fields::Named(FieldsNamed { named: fields, .. }) => {
                    let field_idents = fields.iter().map(|field| &field.ident).collect::<Vec<_>>();

                    // These are allow_omit, because they are appearing inside an aggregate (the anonymous struct)
                    let per_field_digest = fields
                        .iter()
                        .map(|field| {
                            let field_ident = &field.ident;
                            quote! {
                                #field_ident.append_to_transcript_allow_omit(stringify!(#field_ident).as_bytes(), transcript);
                            }
                        })
                        .collect::<Vec<_>>();

                    quote! {
                        Self::#variant_ident{ #(#field_idents),* } => {
                            transcript.append_var_header(context, stringify!(#custom_name).as_bytes(), #which as u32);
                            transcript.append_agg_header(stringify!(#variant_ident).as_bytes(), b"");
                            #(#per_field_digest)*;
                            transcript.append_agg_closer(stringify!(#variant_ident).as_bytes(), b"");
                        }
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics mc_crypto_digestible::Digestible for #ident #ty_generics #where_clause {
            fn append_to_transcript<DT: mc_crypto_digestible::DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                // Per-variant hashing.
                match self {
                    #(#call)*
                }
            }
        }
    };

    Ok(expanded.into())
}

#[proc_macro_derive(Digestible, attributes(digestible))]
pub fn digestible(input: TokenStream) -> TokenStream {
    try_digestible(input).unwrap()
}
