// Copyright (c) 2018-2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs)]

use core::cmp::{Ordering, PartialEq, PartialOrd};

/// A simple type which represents a ratio of two u64 numbers.
///
/// This is fairly limited in scope and meant to support the implementation
/// of partial fill rules.
/// Don't really want to pull a decimal or rational class etc. into the enclave
/// if we can avoid it, this should be much simpler.
#[derive(Copy, Clone, Debug, Eq)]
pub struct U64Ratio {
    // The u64 numerator of the ratio, which has been extended to a u128
    num: u128,
    // The u64 denominator of the ratio, which has been extended to a u128
    denom: u128,
}

impl U64Ratio {
    /// Create a new U64Ratio from a numerator and denominator
    ///
    /// This can fail if the denominator is zero.
    pub fn new(num: u64, denom: u64) -> Option<Self> {
        if denom == 0 {
            None
        } else {
            Some(Self {
                num: num as u128,
                denom: denom as u128,
            })
        }
    }

    /// Multiply a u64 number by the ratio, rounding down.
    ///
    /// This can fail if the result overflows a u64.
    /// Note that this cannot fail if the ratio is <= 1.
    pub fn checked_mul_round_down(&self, val: u64) -> Option<u64> {
        ((val as u128 * self.num) / self.denom).try_into().ok()
    }

    /// Multiply a u64 number by the ratio, rounding up.
    /// Note that this cannot fail if the ratio is <= 1.
    pub fn checked_mul_round_up(&self, val: u64) -> Option<u64> {
        (((val as u128 * self.num) + (self.denom - 1)) / self.denom)
            .try_into()
            .ok()
    }
}

impl PartialEq for U64Ratio {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // Intuitively, to check if two u64 fractions are equal, we want to check
        // if a/b = c/d as rational numbers. However, we would like to avoid the
        // use of floating point numbers or more complex decimal classes, because
        // they introduce more complex types of errors and imprecision.
        //
        // Instead, we multiply both sides of the equation by b and d to clear
        // denominators, and test equality as u128's, which avoids overflow issues.
        //
        // This matches how fractions are defined in abstract algebra:
        // https://en.wikipedia.org/wiki/Field_of_fractions
        (self.num * other.denom).eq(&(other.num * self.denom))
    }
}

impl Ord for U64Ratio {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        // Intuitively, to compare two u64 fractions, we want to compare
        // a/b and c/d as rational numbers. However, as before, we would like to
        // avoid the use of more complex numeric types.
        //
        // Instead, observe that if we clear denominators, we have
        //
        // a/b < c/d
        // iff
        // a*d < c*b
        //
        // because we know both b and d are positive integers here.
        //
        // For the same reason,
        //
        // a/b > c/d
        // iff
        // a*d > c*b
        //
        // Everything has been extended to a u128 to prevent the possibility of
        // overflow.
        (self.num * other.denom).cmp(&(other.num * self.denom))
    }
}

impl PartialOrd for U64Ratio {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_eq() {
        assert_eq!(U64Ratio::new(1, 4).unwrap(), U64Ratio::new(2, 8).unwrap());
        assert_eq!(
            U64Ratio::new(200, 4).unwrap(),
            U64Ratio::new(1000, 20).unwrap()
        );
        assert_ne!(U64Ratio::new(1, 5).unwrap(), U64Ratio::new(1, 4).unwrap());
        assert_ne!(
            U64Ratio::new(u64::MAX, u64::MAX).unwrap(),
            U64Ratio::new(u64::MAX, u64::MAX - 1).unwrap()
        );
    }

    #[test]
    fn ratio_ord() {
        assert!(U64Ratio::new(1, 5).unwrap() < U64Ratio::new(1, 4).unwrap());
        assert!(U64Ratio::new(3, 7).unwrap() > U64Ratio::new(2, 8).unwrap());
        assert!(U64Ratio::new(1, 4).unwrap() >= U64Ratio::new(2, 8).unwrap());
        assert!(U64Ratio::new(6, 10).unwrap() <= U64Ratio::new(13, 20).unwrap());
        assert!(
            U64Ratio::new(u64::MAX, u64::MAX).unwrap()
                < U64Ratio::new(u64::MAX, u64::MAX - 1).unwrap()
        );
        assert!(
            U64Ratio::new(u64::MAX - 1, u64::MAX).unwrap()
                <= U64Ratio::new(u64::MAX, u64::MAX).unwrap()
        );
    }

    #[test]
    fn checked_mul() {
        let r = U64Ratio::new(4, 8).unwrap();

        assert_eq!(r.checked_mul_round_down(10), Some(5));
        assert_eq!(r.checked_mul_round_up(10), Some(5));
        assert_eq!(r.checked_mul_round_down(11), Some(5));
        assert_eq!(r.checked_mul_round_up(11), Some(6));
        assert_eq!(r.checked_mul_round_down(12), Some(6));
        assert_eq!(r.checked_mul_round_up(12), Some(6));
        assert_eq!(r.checked_mul_round_down(u64::MAX), Some(u64::MAX / 2));
        assert_eq!(r.checked_mul_round_up(u64::MAX), Some(u64::MAX / 2 + 1));

        let r = U64Ratio::new(4, 7).unwrap();
        assert_eq!(r.checked_mul_round_down(100), Some(57));
        assert_eq!(r.checked_mul_round_up(100), Some(58));
        assert_eq!(r.checked_mul_round_down(101), Some(57));
        assert_eq!(r.checked_mul_round_up(101), Some(58));
        assert_eq!(r.checked_mul_round_down(102), Some(58));
        assert_eq!(r.checked_mul_round_up(102), Some(59));

        assert_eq!(
            r.checked_mul_round_down(u64::MAX),
            Some(10540996613548315208)
        );
        assert_eq!(r.checked_mul_round_up(u64::MAX), Some(10540996613548315209));
    }

    #[test]
    fn checked_mul_maxed() {
        let r = U64Ratio::new(u64::MAX, u64::MAX).unwrap();
        assert_eq!(r.checked_mul_round_up(u64::MAX), Some(u64::MAX));
        assert_eq!(r.checked_mul_round_down(u64::MAX), Some(u64::MAX));
    }

    #[test]
    fn checked_mul_overflows() {
        let r = U64Ratio::new(u64::MAX, u64::MAX - 1).unwrap();
        assert_eq!(r.checked_mul_round_up(u64::MAX), None);
        assert_eq!(r.checked_mul_round_down(u64::MAX), None);
    }
}
