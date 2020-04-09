// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::{
    amount::Amount,
    ring_signature::{Blinding, CurveScalar},
};
use curve25519_dalek::scalar::Scalar;
use keys::{RistrettoPrivate, RistrettoPublic};
use proptest::prelude::*;

/// Generates an arbitrary Scalar.
pub fn arbitrary_scalar() -> impl Strategy<Value = Scalar> {
    any::<[u8; 32]>().prop_map(Scalar::from_bytes_mod_order)
}

/// Generates an arbitrary CurveScalar.
pub fn arbitrary_curve_scalar() -> impl Strategy<Value = CurveScalar> {
    arbitrary_scalar().prop_map(CurveScalar::from)
}

/// Generates an arbitrary blinding.
pub fn arbitrary_blinding() -> impl Strategy<Value = Blinding> {
    arbitrary_curve_scalar()
}

/// Generates an arbitrary RistrettoPrivate key.
pub fn arbitrary_ristretto_private() -> impl Strategy<Value = RistrettoPrivate> {
    arbitrary_scalar().prop_map(RistrettoPrivate::from)
}

/// Generates an arbitrary RistrettoPublic key.
pub fn arbitrary_ristretto_public() -> impl Strategy<Value = RistrettoPublic> {
    arbitrary_ristretto_private().prop_map(|private_key| RistrettoPublic::from(&private_key))
}

prop_compose! {
    /// Generates an arbitrary amount with value in [0,max_value].
    pub fn arbitrary_amount(max_value: u64, shared_secret: RistrettoPublic)
                (value in 0..=max_value, blinding in arbitrary_blinding()) -> Amount {
            Amount::new(value,  blinding, &shared_secret).unwrap()
    }
}
