// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Crate used to ensure we can build to the wasm target.

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn add(a: u32, b: u32) -> u32 {
    a + b
}

mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn add_works() {
        assert_eq!(add(1, 2), 3);
    }
}
