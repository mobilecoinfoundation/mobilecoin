//! This module contains an implementation of constant-time integer division.
//! Only u64's are supported.
//!
//! The algorithm here is an adaptation of an algorithm described in Soatok's
//! blog: https://soatok.blog/2020/08/27/soatoks-guide-to-side-channel-attacks/
//! Note however, that this is basically just long division, for binary numbers.
//!
//! The blog post does not contain a proof of correctness for the algorithm,
//! however, we will give our own exposition now.
//!
//! Unsigned integer division means, given a number and divisor (N and D),
//! we want to produce quotient and remainder (Q and R) such that:
//!
//! N = Q * D + R
//!
//! where 0 <= R < Q ("R is fully reduced").
//!
//! This solution is unique for any N and D != 0.
//!
//! The idea of the algorithm is to look at the bit representation of N,
//! and consider the sequence of "prefixes" of this number.
//! So if N = 101101b for instance,
//! we will consider the sequence.
//! 1b
//! 10b
//! 101b
//! 1011b
//! 10110b
//! 101101b
//!
//! At each step we will compute the quotient and remainder when divided by D.
//! Let b_i denote the i'th bit of N.
//!
//! If at the i'th step, we have
//!
//! N_i = Q_i * D + R_i
//!
//! being fully reduced, then in the next step, we have
//!
//! N_{i+1} = 2 * N_i + b_i
//!
//! and we want to compute a fully reduced equation dividing N_{i+1} by D.
//!
//! Substituting for N_i and expanding, we have
//!
//! N_{i+1} = 2 * Q_i * D + 2 * R_i + b_i
//!
//! This looks almost like a division of N_{i+1} by D as required, but it may
//! not be fully reduced, because we may have 2 * R_i + b_i > D.
//!
//! However, since R_i < D, we know that 2 * R_i + b_i < 2 * D.
//! So to fully reduce the remainder, we have to subtract D at most once.
//!
//! We can compute 2 * R_i + b_i in constant time, and then in constant time
//! test if it is less than D. Then we can subtract D, and conditionally assign
//! it with the result. We can also conditionally add one to 2 * Q_i in that
//! case. Once we have done this, we will have successfully divided N_{i+1} by
//! D, and we can proceed to the next digit.
//!
//! On x86-64 we can assume that wrapping_sub and wrapping_add integer
//! operations are constant time. We use the subtle crate for constant time
//! comparisons and conditional assignment.

use subtle::{ConditionallySelectable, ConstantTimeLess};

/// Divide one u64 integer by another in constant time.
///
/// Arguments:
/// * n: The number being divided
/// * d: The divisor
///
/// Both n and d are considered secrets for constant time purposes.
///
/// Returns:
/// * q: The quotient
/// * r: The remainder
///
/// Preconditions: d is nonzero
///
/// Note: This function always takes the same number of operations on x86-64.
///
/// We estimate that it probably takes on the order of tens of thousands of
/// cycles. The most expensive operation in the loop is ct_lt, which also crawls
/// 64 bits, and we do the loop 64 times.
///
/// If this needs to be faster, some approaches are detailed here:
/// https://stackoverflow.com/a/31718095/3598119
/// * Use x86-64 specific stuff calling to clz or similar.
/// * Use the de Brujin multiplication trick.
///
/// However it may take some work to implement those in a way that is actually
/// constant time and is faster.
pub fn ct_u64_divide(n: u64, d: u64) -> (u64, u64) {
    assert!(d != 0, "division by zero");

    let mut q = 0u64;
    let mut r = 0u64;

    for i in (0u64..64u64).rev() {
        // This is a logical left shift and rust does not check for overflow.
        // This is similar to an unchecked mul by 2 on x86.
        q = q << 1;
        r = r << 1;

        // Select i'th bit of n using bitmasking, and add it to r
        // Wrapping add is used to avoid any overflow checks.
        r = r.wrapping_add((n >> i) & 1);

        // Test if r >= d in constant time.
        let must_reduce = !r.ct_lt(&d);

        // Compute the difference in case it is necessary. No overflow checks.
        let r_sub_d = r.wrapping_sub(d);

        // If r needs to be reduced, then it becomes r_sub_d.
        r.conditional_assign(&r_sub_d, must_reduce);

        // If reduction happened, then we must add one to q.
        q = q.wrapping_add(must_reduce.unwrap_u8() as u64);
    }
    (q, r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_u64_divide() {
        assert_eq!(ct_u64_divide(0, 1), (0, 0));
        assert_eq!(ct_u64_divide(3, 1), (3, 0));
        assert_eq!(ct_u64_divide(3, 2), (1, 1));
        assert_eq!(ct_u64_divide(3, 4), (0, 3));
        assert_eq!(ct_u64_divide(33, 4), (8, 1));
        assert_eq!(ct_u64_divide(33, 5), (6, 3));
        assert_eq!(ct_u64_divide(33, 6), (5, 3));
        assert_eq!(ct_u64_divide(33, 7), (4, 5));
        assert_eq!(ct_u64_divide(33, 8), (4, 1));
        assert_eq!(ct_u64_divide(33, 9), (3, 6));
        assert_eq!(ct_u64_divide(33, 10), (3, 3));
        assert_eq!(ct_u64_divide(33, 11), (3, 0));
        assert_eq!(ct_u64_divide(77, 100), (0, 77));
        assert_eq!(ct_u64_divide(777, 100), (7, 77));
    }
}
