// Copyright (c) 2018-2021 The MobileCoin Foundation

use proc_macro::Diagnostic;
use std::result;
use syn::parse::Error as SynError;

pub struct DiagnosticError {
    diagnostic: Diagnostic,
    #[allow(dead_code)]
    syn_error: Option<SynError>,
}

impl DiagnosticError {
    #[allow(dead_code)]
    pub fn new(diagnostic: Diagnostic) -> DiagnosticError {
        DiagnosticError {
            diagnostic,
            syn_error: None,
        }
    }
    pub fn new_with_syn_error(diagnostic: Diagnostic, syn_error: SynError) -> DiagnosticError {
        DiagnosticError {
            diagnostic,
            syn_error: Some(syn_error),
        }
    }

    #[allow(dead_code)]
    pub fn source(&self) -> Option<&SynError> {
        self.syn_error.as_ref()
    }

    pub fn emit(self) {
        self.diagnostic.emit();
    }
}

pub type Result<T> = result::Result<T, DiagnosticError>;
