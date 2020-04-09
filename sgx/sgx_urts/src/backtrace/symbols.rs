// Copyright (c) 2018-2020 MobileCoin Inc.

/// Provide a stubbed out implementation of SymbolContext
/// Use will only get addresses, they can look them up manually with nm or objdump
use super::symbol_context::*;

pub struct Symbolicator {}

impl Symbolicator {
    pub fn new(_: &CString) -> Self {
        Symbolicator {}
    }
    pub fn new_null() -> Self {
        Symbolicator {}
    }
}
impl SymbolContext for Symbolicator {
    fn is_null(&self) -> bool {
        true
    }
    fn foreach_symbol_fileline(
        &mut self,
        _frame: &Frame,
        _f: &mut dyn FnMut(&[u8], u32) -> io::Result<()>,
    ) -> io::Result<bool> {
        Ok(false)
    }
    fn resolve_symname(
        &mut self,
        _frame: &Frame,
        f: &mut dyn FnMut(Option<&str>) -> io::Result<()>,
    ) -> io::Result<()> {
        f(None)
    }
}
