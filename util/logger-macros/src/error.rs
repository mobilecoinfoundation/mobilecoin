// Copyright (c) 2018-2020 MobileCoin Inc.

use proc_macro::Diagnostic;
use std::result;
use syn;

pub struct DiagnosticError {
    diagnostic: Diagnostic,
    #[allow(dead_code)]
    syn_error: Option<syn::parse::Error>,
}

impl DiagnosticError {
    #[allow(dead_code)]
    pub fn new(diagnostic: Diagnostic) -> DiagnosticError {
        DiagnosticError {
            diagnostic,
            syn_error: None,
        }
    }
    pub fn new_with_syn_error(
        diagnostic: Diagnostic,
        syn_error: syn::parse::Error,
    ) -> DiagnosticError {
        DiagnosticError {
            diagnostic,
            syn_error: Some(syn_error),
        }
    }

    #[allow(dead_code)]
    pub fn source(&self) -> Option<&syn::parse::Error> {
        self.syn_error.as_ref()
    }

    pub fn emit(self) {
        self.diagnostic.emit();
    }
}

pub type Result<T> = result::Result<T, DiagnosticError>;
