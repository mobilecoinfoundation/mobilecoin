// Copyright (c) 2018-2022 The MobileCoin Foundation

// The `quote!` macro requires deep recursion.
#![recursion_limit = "4096"]

extern crate alloc;
extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DataEnum, DataStruct, DeriveInput, Fields, FieldsNamed, FieldsUnnamed,
    Generics, Ident, Lit, Meta, NestedMeta,
};

/// These are configuration options that are selected by #[digestible(..)]
/// attributes at struct or enum declaration. They are parsed from the
/// DeriveInput::attrs field.
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

/// Configuration options for individual fields inside a struct.
/// They are set using the #[digestible(..)] directive.
#[derive(Default, Clone, Debug)]
struct FieldAttributeConfig {
    /// Allows skipping the hashing of a field if it's value is equal to
    /// something. This is a backwards compatibility tool that allows adding
    /// new fields without affecting the hash of existing objects that do
    /// not have the field set.
    pub omit_when: Option<Lit>,

    /// Never omit the hashing of a field.
    /// This is a backwards compatibility tool that allows us to skip omitting
    /// fields that are now omitted when not set (the behavior for
    /// &[u8]/Vec<u8>/&str/String has changed over time).
    pub never_omit: bool,

    /// Whether we should rename this field, using the given
    /// string for the new name, for purpose of hashing.
    /// This is a backwards compatibility tool.
    pub rename: Option<String>,
}

impl FieldAttributeConfig {
    // Apply a nested meta item from syn to the current config state
    pub fn apply_meta(&mut self, nested_meta: &NestedMeta) -> Result<(), &'static str> {
        match nested_meta {
            NestedMeta::Lit(_) => {
                return Err("Unexpected digestible literal attribute");
            }
            NestedMeta::Meta(meta) => match meta {
                Meta::NameValue(mnv) => {
                    if mnv.path.is_ident("omit_when") {
                        if self.never_omit {
                            return Err("omit_when cannot be used together with never_omit");
                        } else if self.omit_when.is_some() {
                            return Err("omit_when cannot appear twice as an attribute");
                        } else {
                            self.omit_when = Some(mnv.lit.clone());
                        }
                    } else if mnv.path.is_ident("name") {
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

                Meta::Path(path) => {
                    if path.is_ident("never_omit") {
                        if self.omit_when.is_some() {
                            return Err("never_omit cannot be used together with omit_when");
                        } else {
                            self.never_omit = true;
                        }
                    } else {
                        return Err(
                            "unexpected digestible attribute (unrecognized \"path\" element)",
                        );
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
impl TryFrom<&[Attribute]> for FieldAttributeConfig {
    type Error = &'static str;

    fn try_from(src: &[Attribute]) -> Result<Self, &'static str> {
        let mut result = FieldAttributeConfig::default();

        for attr in src {
            if attr.path.is_ident("digestible") {
                if let Meta::List(meta) = attr.parse_meta().unwrap() {
                    for meta_item in meta.nested.iter() {
                        result.apply_meta(meta_item)?;
                    }
                }
            }
        }

        Ok(result)
    }
}

// This is the main entrypoint for `derive(Digestible)`
fn try_digestible(input: TokenStream) -> Result<TokenStream, &'static str> {
    let input: DeriveInput = syn::parse(input).unwrap();

    // The rust identifier for this struct or enum
    let ident = input.ident;
    // The generics associated to this struct or enum
    let generics = &input.generics;
    // Read any #[digestible(...)]` attributes on this struct or enum and parse them
    let attr_config = AttributeConfig::try_from(&input.attrs[..])?;

    if attr_config.transparent {
        // Handle the `digestible(transparent)` option
        match input.data {
            Data::Struct(variant_data) => {
                try_digestible_struct_transparent(&ident, generics, &variant_data)
            }
            Data::Enum(variant_data) => {
                try_digestible_enum_transparent(&ident, generics, &variant_data)
            }
            Data::Union(..) => Err("Digestible cannot be derived for a union"),
        }
    } else {
        // If the user specified a name, that's the custom name, otherwise use the rust
        // ident
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

// Implement digestible for a struct, by creating an agg node for it,
// and making each struct field a child.
// Children are appended to transcript using `append_to_transcript_allow_omit`,
// because the allow omit is what permits schema evolution to occur.
fn try_digestible_struct(
    ident: &Ident,
    custom_name: &Ident,
    generics: &Generics,
    variant_data: &DataStruct,
) -> Result<TokenStream, &'static str> {
    // Get the sequence of fields out of syn, as a Vec<&syn::Field>
    let fields: Vec<&syn::Field> = match &variant_data.fields {
        Fields::Named(FieldsNamed { named: fields, .. })
        | Fields::Unnamed(FieldsUnnamed {
            unnamed: fields, ..
        }) => fields.into_iter().collect(),
        Fields::Unit => Vec::new(),
    };

    // This is the tokens representing, bringing the transcript to each field
    let call : Vec<proc_macro2::TokenStream> = fields
        .into_iter()
        .enumerate()
        .map(|(idx, field)| {
            match &field.ident {
                // this is a regular struct, and the field has an identifier
                Some(field_ident) => {
                    // Read any #[digestible(...)]` attributes on this field and parse them
                    let attr_config = FieldAttributeConfig::try_from(&field.attrs[..])?;

                    let hashing_name: String = attr_config.rename.clone().unwrap_or_else(|| field_ident.to_string());

                    if attr_config.never_omit {
                        Ok(quote! {
                            self.#field_ident.append_to_transcript(#hashing_name.as_bytes(), transcript);
                        })
                    } else if let Some(omit_when) = attr_config.omit_when {
                        Ok(quote! {
                            if self.#field_ident != #omit_when {
                                self.#field_ident.append_to_transcript_allow_omit(#hashing_name.as_bytes(), transcript);
                            }
                        })
                    } else {
                        Ok(quote! {
                            self.#field_ident.append_to_transcript_allow_omit(#hashing_name.as_bytes(), transcript);
                        })
                    }
                }
                // this is a tuple struct, and the field doesn't have an identifier
                // we have to make a syn object corresponding to the index, and use it in the quote! macro
                None => {
                    // Read any #[digestible(...)]` attributes on this field and parse them
                    let attr_config = FieldAttributeConfig::try_from(&field.attrs[..])?;

                    if attr_config.rename.is_some() { panic!("name attribute is not supported on fields of tuple structs") }

                    let index = syn::Index::from(idx);

                    if attr_config.never_omit {
                        Ok(quote! {
                            self.#index.append_to_transcript(stringify!(#index).as_bytes(), transcript);
                        })
                    } else if let Some(omit_when) = attr_config.omit_when {
                        Ok(quote! {
                            if self.#index != #omit_when {
                                self.#index.append_to_transcript_allow_omit(stringify!(#index).as_bytes(), transcript);
                            }
                        })
                    } else {
                        Ok(quote! {
                            self.#index.append_to_transcript_allow_omit(stringify!(#index).as_bytes(), transcript);
                        })
                    }
                }
            }
        })
        .collect::<Result<Vec<_>, &'static str>>()?;

    // Final expanded result
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // We implement append_to_transcript for the struct by
    // first creating an agg header, then appending each field,
    // then creating a matching agg closer
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

// digestible(transparent) means that, this struct is a "wrapper" around a
// single value, and when digesting it, we don't create an agg node.
// Instead, we forward calls to `append_to_transcript`
// and `append_to_transcript_allow_omit` directly to the inner value.
//
// This is only allowed when the struct has exactly one field
fn try_digestible_struct_transparent(
    ident: &Ident,
    generics: &Generics,
    variant_data: &DataStruct,
) -> Result<TokenStream, &'static str> {
    // Get the sequence of fields out of syn, as a Vec<syn::Field>
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
        return Err("digestible cannot be derived transparently for a struct with no fields");
    }
    if fields.len() > 1 {
        return Err("digestible cannot be derived transparently for a struct or tuple with more than one field");
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
    let call : Vec<proc_macro2::TokenStream> = variant_data
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
                // we append an appropriate variant header, then append a "none" node to be its child.
                // There must be a child node, even if it is None, to prevent ambiguity
                Fields::Unit => {
                    quote! {
                        Self::#variant_ident => {
                            transcript.append_var_header(context, stringify!(#custom_name).as_bytes(), #which as u32);
                            transcript.append_none(stringify!(#variant_ident).as_bytes());
                        },
                    }
                }

                // For an enum variant with one nameless member, e.g. SomeEnum::Possibility(u32), which is the 3rd possibility
                // we generate code like this, which appends a var_header, and then immediately the child value.
                // The child value may not be omitted.
                //
                // Self::Possibility(val) => {
                //   transcript.append_var_header(context, "SomeEnum".as_bytes(), 3 as u32);
                //   val.append_to_transcript("Possibility".as_bytes(), transcript);
                // }
                //
                // For an enum variant that multiple anonymous fields (e.g. SomeEnum::MyVariant(u32,
                // u64)) we generate code that creates an anonymous aggregate as the child of the variant,
                // and makes the fields children of that aggregate.
                // This child node is the same as what we would get if handling a struct tuple, whose name
                // was the empty string.
                // For example:
                //
                // Self::MyVariant(field_0, field_1) => {
                //   transcript.append_var_header(context, "SomeEnum".as_bytes(), 3 as u32);
                //   transcript.append_agg_header("MyVariant".as_bytes(), b"");
                //   field_0.append_to_transcript_allow_omit("0".as_bytes(), transcript);
                //   field_1.append_to_transcript_allow_omit("1".as_bytes(), transcript);
                //   transcript.append_agg_closer("MyVariant".as_bytes(), b"");
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
                // we generate code that creates an anonymous aggregate as the child of the variant,
                // and makes the fields children of that aggregate.
                // This child node is the same as what we would get if handling a struct, whose name
                // was the empty string.
                //
                // For example:
                //
                // Self::MyVariant { a, b } => {
                //   transcript.append_var_header(context, "SomeEnum".as_bytes(), 3 as u32);
                //   transcript.append_agg_header("MyVariant".as_bytes(), b"");
                //   a.append_to_transcript_allow_omit("a".as_bytes(), transcript);
                //   b.append_to_transcript_allow_omit("b".as_bytes(), transcript);
                //   transcript.append_agg_closer("MyVariant".as_bytes(), b"");
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

fn try_digestible_enum_transparent(
    ident: &Ident,
    generics: &Generics,
    variant_data: &DataEnum,
) -> Result<TokenStream, &'static str> {
    let (call, call_allow_omit) : (Vec<proc_macro2::TokenStream>, Vec<proc_macro2::TokenStream>) = variant_data
        .variants
        .iter()
        .map(|variant| {
            let variant_ident = &variant.ident;

            match &variant.fields {
                // Enum variant that doesn't have associated data (e.g. SomeEnum::MyVariant)
                Fields::Unit => {
                    panic!("Unit variants (options without associated data) cannot be used with digestible(transparent) on an enum");
                }

                // For an enum variant with one nameless member, e.g. SomeEnum::Possibility(u32),
                // we skip directly to adding the member to the transcript, so that nothing about the
                // enum enters the transcript (it is transparent).
                //
                // The child value may not be omitted.
                // However, if append_to_transcript_allow_omit is used then the child may be omitted.
                //
                // Self::Possibility(val) => {
                //   val.append_to_transcript(context, transcript);
                // }
                Fields::Unnamed(FieldsUnnamed {
                    unnamed: fields, ..
                }) => {
                    if fields.len() == 1 {
                        (quote! {
                            Self::#variant_ident(val) => {
                                val.append_to_transcript(context, transcript);
                            }
                        },
                        quote! {
                            Self::#variant_ident(val) => {
                                val.append_to_transcript_allow_omit(context, transcript);
                            }
                        })
                    } else {
                        panic!("Exactly zero or one unnamed fields may be present when using digestible(transparent) on an enum");
                    }
                }

                // For an enum variant that has named fields (e.g. SomeEnum::MyVariant { a: u64, b: u64 },
                // we cannot digest it transparently.
                Fields::Named(FieldsNamed { .. }) => {
                    panic!("Named fields cannot be used when using digestible(transparent) on an enum");
                }
            }
        })
        .unzip();

    // Safety check: Try to make sure each variant of the enum has a different type.
    // In the future we could allow a special way to bypass this check.
    for i in 1..variant_data.variants.len() {
        for j in 0..i {
            let ith_type = match &variant_data.variants[i].fields {
                Fields::Unnamed(FieldsUnnamed {
                    unnamed: fields, ..
                }) => &fields[0].ty,
                _ => panic!("Unexpected variant"),
            };

            let jth_type = match &variant_data.variants[j].fields {
                Fields::Unnamed(FieldsUnnamed {
                    unnamed: fields, ..
                }) => &fields[0].ty,
                _ => panic!("Unexpected variant"),
            };

            if ith_type == jth_type {
                panic!("The types of the {j}'th and {i}'th variants of {ident} appear to be the same. When using digestible(transparent), this is highly suspect");
            }
        }
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics mc_crypto_digestible::Digestible for #ident #ty_generics #where_clause {
            fn append_to_transcript<DT: mc_crypto_digestible::DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                // Per-variant hashing.
                match self {
                    #(#call)*
                }
            }
            fn append_to_transcript_allow_omit<DT: mc_crypto_digestible::DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                // Per-variant hashing with allow_omit
                match self {
                    #(#call_allow_omit)*
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
