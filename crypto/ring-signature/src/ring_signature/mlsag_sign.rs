// Copyright (c) 2018-2022 The MobileCoin Foundation

//! RingMLSAG signing internals

use core::fmt::Debug;

use curve25519_dalek::ristretto::RistrettoPoint;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

use crate::{
    ring_signature::{
        challenge, hash_to_point, CurveScalar, Error, KeyImage, PedersenGens, Ring, Scalar,
        B_BLINDING,
    },
    Commitment,
};

/// MLSAG Signing object, provides context for generating ring signatures
#[derive(Debug)]
pub struct MlsagSignParams<'a> {
    /// Size of ring to be signed
    pub ring_size: usize,
    /// Message to be signed.
    pub message: &'a [u8],
    /// The index in the ring of the real input.
    pub real_index: usize,
    /// The real input's private key.
    pub onetime_private_key: &'a RistrettoPrivate,
    /// Value of the real input.
    pub value: u64,
    /// Blinding of the real input.
    pub blinding: &'a Scalar,
    /// The output amount's blinding factor.
    pub output_blinding: &'a Scalar,
    /// The pedersen generator to use for this commitment and signature
    pub generator: &'a PedersenGens,
    /// If true, check that the value of inputs equals
    pub check_value_is_preserved: bool,
}

impl<'a> MlsagSignParams<'a> {
    /// Sign a ring of input addresses and amount commitments using a modified
    /// MLSAG
    ///
    /// Returns the signed key_image and c_zero scalar
    pub fn sign(
        &self,
        ring: impl Ring,
        // Note: this `mut rng` can just be `rng` if this is merged upstream:
        // https://github.com/dalek-cryptography/curve25519-dalek/pull/394
        rng: impl CryptoRngCore,
        responses: &mut [CurveScalar],
    ) -> Result<(KeyImage, CurveScalar), Error> {
        let ring_size = ring.size();

        if self.real_index >= ring_size {
            return Err(Error::IndexOutOfBounds);
        }

        // Check buffer lengths are correct

        // `responses` must contain `2 * ring_size` elements.
        if responses.len() != 2 * ring_size {
            return Err(Error::LengthMismatch(2 * ring_size, responses.len()));
        }

        // Ring must decompress.
        ring.check()?;

        // Setup signing context
        let mut sign_ctx = MlsagSignCtx::init(&self, rng, responses)?;

        // Iterate around the ring, starting at real_index.
        // NOTE: THIS REORDERING IS CRITICAL FOR PIECEWISE COMPUTATION
        for n in 0..ring_size {
            let i = (self.real_index + n) % ring_size;
            let tx_out = &ring.index(i)?;

            sign_ctx.update(&self, i, tx_out)?;
        }

        // "Close the loop" by computing responses for the real index.
        let (key_image, c_zero) = sign_ctx.finalise(&self)?;

        Ok((key_image, c_zero))
    }
}

/// MLSAG signing context, supports incremental computation for ring signing.
///
/// WARNING: MISUSE OF THIS API MAY GENERATE INVALID RINGS,
/// SEE [`MlsagSign`] FOR A PREFERRED HIGHER LEVEL ABSTRACTION
#[derive(Debug, Zeroize)]
pub struct MlsagSignCtx<R: AsMut<[CurveScalar]>> {
    alpha_0: Scalar,
    alpha_1: Scalar,
    G: RistrettoPoint,
    I: RistrettoPoint,

    /// Cache real input for balance checking
    #[zeroize(skip)]
    real_input: Option<(RistrettoPublic, Commitment)>,

    /// Number of rings computed
    ring_count: usize,

    responses: R,

    real_challenge: Option<Scalar>,
    last_challenge: Option<Scalar>,
    zeroth_challenge: Option<Scalar>,

    #[zeroize(skip)]
    key_image: KeyImage,

    #[zeroize(skip)]
    output_commitment: Commitment,

    complete: bool,
}

#[allow(dead_code)]
impl<R: AsRef<[CurveScalar]> + AsMut<[CurveScalar]>> MlsagSignCtx<R> {
    /// Initialise signing state, including `challenges` and `responses` working
    /// buffers
    pub fn init<'a>(
        params: &'a MlsagSignParams<'a>,
        mut rng: impl CryptoRngCore,
        mut responses: R,
    ) -> Result<Self, Error> {
        let G = B_BLINDING;
        debug_assert!(
            params.generator.B_blinding == G,
            "basepoint for blindings mismatch"
        );

        let r = responses.as_mut();

        // Check buffer lengths are correct for ring size
        if r.len() != params.ring_size * 2 {
            return Err(Error::LengthMismatch(params.ring_size * 2, r.len()));
        }

        // Generate KeyImage from generated transaction private key
        let key_image = KeyImage::from(params.onetime_private_key);

        // The uncompressed key_image.
        let I = key_image.point.decompress().ok_or(Error::InvalidKeyImage)?;

        // Uncompressed output commitment.
        // This ensures that each address and commitment encodes a valid Ristretto
        // point.
        let output_commitment =
            Commitment::new(params.value, *params.output_blinding, params.generator);

        // Responses `r_{0,0}, r_{0,1}, ... , r_{ring_size-1,0}, r_{ring_size-1,1}`.
        r.iter_mut()
            .for_each(|v| *v = CurveScalar::from(Scalar::zero()));

        for i in 0..params.ring_size {
            if i == params.real_index {
                continue;
            }
            r[2 * i].scalar = Scalar::random(&mut rng);
            r[2 * i + 1].scalar = Scalar::random(&mut rng);
        }

        Ok(Self {
            G,
            I,
            key_image,
            output_commitment,
            alpha_0: Scalar::random(&mut rng),
            alpha_1: Scalar::random(&mut rng),
            ring_count: 0,
            real_input: None,
            real_challenge: None,
            last_challenge: None,
            zeroth_challenge: None,
            responses,
            complete: false,
        })
    }

    /// Update signing context with provided tx_out.
    ///
    /// NOTE THIS _MUST_ FOLLOW A CALL TO INIT AND TRAVERSE THE RING STARTING
    /// WITH THE REAL TXOUT
    pub fn update<'a>(
        &mut self,
        params: &MlsagSignParams<'a>,
        i: usize,
        tx_out: &(RistrettoPublic, Commitment),
    ) -> Result<(), Error> {
        let MlsagSignParams {
            real_index,
            message,
            ring_size,
            ..
        } = params;

        let responses = self.responses.as_mut();

        // Check tx_out index matches current state
        if i != (real_index + self.ring_count) % ring_size {
            return Err(Error::UnexpectedTxout);
        }

        let (P_i, input_commitment) = tx_out;

        let (L0, R0, L1) = if i == *real_index {
            // c_{i+1} = Hn( m | key_image | alpha_0 * G | alpha_0 * Hp(P_i) | alpha_1 * G )
            //         = Hn( m | key_image |      L0     |         R0        |      L1     )
            //
            // where P_i is the i^th onetime public key.
            // There is no R1 term because no key image is needed for the commitment to
            // zero.

            let L0 = self.alpha_0 * self.G;
            let R0 = self.alpha_0 * hash_to_point(P_i);
            let L1 = self.alpha_1 * self.G;
            (L0, R0, L1)
        } else {
            let last_challenge = match self.last_challenge {
                Some(c) => c,
                // TODO: replace with a better error
                None => return Err(Error::IndexOutOfBounds),
            };

            // c_{i+1} = Hn( m | key_image | r_{i,0} * G + c_i * P_i | r_{i,0} * Hp(P_i) +
            // c_i * I | r_{i,1} * G + c_i * Z_i )         = Hn( m |
            // key_image |           L0            |               R0            |
            // L1          )
            //
            // where:
            // * P_i is the i^th onetime public key.
            // * I is the key image of the real input's private key,
            // * Z_i is the i^th "commitment to zero" = output_commitment -
            //   input_commitment.
            //
            // There is no R1 term because no key image is needed for the commitment to
            // zero.

            let L0 = responses[2 * i].scalar * self.G + last_challenge * P_i.as_ref();
            let R0 = responses[2 * i].scalar * hash_to_point(P_i) + last_challenge * self.I;
            let L1 = responses[2 * i + 1].scalar * self.G
                + last_challenge * (self.output_commitment.point - input_commitment.point);
            (L0, R0, L1)
        };

        // Generate the challenge for the _next_ ring entry
        let c = challenge(message, &self.key_image, &L0, &R0, &L1);

        // Cache the real input for balance checking
        if i == *real_index {
            self.real_input = Some(tx_out.clone());
        }

        // This logic is a little strange because we're generating the (i+1)th
        // challenge, which can't be cached at step i because this might not yet be
        // generated...

        // If the next entry is the real entry, store the challenge for balance checking
        if (i + 1) % ring_size == *real_index {
            // Cache real challenge
            self.real_challenge = Some(c.clone());
        }

        // If the next entry is the zeroth entry, store c_zero
        if (i + 1) % ring_size == 0 {
            self.zeroth_challenge = Some(c.clone());
        }

        // Store the generated challenge for the next iteration
        self.last_challenge = Some(c.clone());

        self.ring_count += 1;

        Ok(())
    }

    /// Finalise MLSAG signing operation
    pub fn finalise<'a>(
        &mut self,
        params: &'a MlsagSignParams<'a>,
    ) -> Result<(KeyImage, CurveScalar), Error> {
        let MlsagSignParams {
            ring_size,
            real_index,
            ..
        } = params;

        let responses = self.responses.as_mut();

        // Check ring size matches added entries
        if *ring_size != self.ring_count {
            return Err(Error::IndexOutOfBounds);
        }

        // Check we have zeroth and real challenges
        let (_c_real, _c_zero) = match (self.real_challenge, self.zeroth_challenge) {
            (Some(r), Some(z)) => (r, z),
            _ => return Err(Error::InvalidState),
        };

        // "Close the loop" by computing responses for the real index.

        let s: Scalar = *params.onetime_private_key.as_ref();
        responses[2 * real_index].scalar = self.alpha_0 - _c_real * s;

        let z: Scalar = *params.output_blinding - *params.blinding;
        responses[2 * real_index + 1].scalar = self.alpha_1 - _c_real * z;

        if params.check_value_is_preserved {
            let (_, input_commitment) = match self.real_input {
                Some(v) => v,
                None => return Err(Error::IndexOutOfBounds),
            };

            let difference: RistrettoPoint = self.output_commitment.point - input_commitment.point;
            if difference != (z * self.G) {
                return Err(Error::ValueNotConserved);
            }
        }

        self.complete = true;

        Ok((self.key_image.clone(), CurveScalar::from(_c_zero)))
    }

    /// Fetch responses from a -completed- signer context
    ///
    /// Returns a slice of responses or None if incomplete
    pub fn responses(&self) -> Option<&[CurveScalar]> {
        match self.complete {
            true => Some(self.responses.as_ref()),
            false => None,
        }
    }
}
