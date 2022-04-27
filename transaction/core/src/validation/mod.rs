// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Validation routines for a MobileCoin transaction

mod error;
mod validate;

pub use self::{
    error::{TransactionValidationError, TransactionValidationResult},
    validate::{
        validate, validate_inputs_are_sorted, validate_key_images_are_unique,
        validate_masked_token_id_exists, validate_membership_proofs, validate_memo_exists,
        validate_no_masked_token_id_exists, validate_no_memo_exists, validate_number_of_inputs,
        validate_number_of_outputs, validate_outputs_are_sorted,
        validate_outputs_public_keys_are_unique, validate_ring_elements_are_sorted,
        validate_ring_elements_are_unique, validate_ring_sizes, validate_signature,
        validate_tombstone, validate_transaction_fee, validate_tx_out,
    },
};
