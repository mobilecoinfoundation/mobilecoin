use digest::{generic_array, Digest};
use generic_array::typenum::{IsGreaterOrEqual, B1, U32};
use mc_crypto_digestible::DigestTranscript;

/// An object which implements the DigestTranscript API over a cryptographic
/// digest function.
///
/// `append_bytes(context, data)` is implemented by providing framing for
/// context, then appending it, then providing framing for data, then appending
/// it.
///
/// As long as the chosen digest function used is actually collision-resistant,
/// then this can be used as a drop-in for MerlinTranscript, for purposes of
/// Digestible crate.
///
/// This is not and cannot be a fully-general drop-in for Merlin transcripts,
/// especially when multiple rounds of challenge-bytes extraction are taking
/// place.
///
/// The best use-case for something like this is when e.g. you MUST create an
/// ed25519ph signature, and MUST have a SHA512 hasher into which your structure
/// has been correctly marshalled.
pub struct PseudoMerlin<D>
where
    D: Digest,
    <D as Digest>::OutputSize: IsGreaterOrEqual<U32, Output = B1>,
{
    pub inner: D,
}

#[allow(non_snake_case)]
#[inline]
pub fn PseudoMerlin<D>(digest: D) -> PseudoMerlin<D>
where
    D: Digest,
    <D as Digest>::OutputSize: IsGreaterOrEqual<U32, Output = B1>,
{
    PseudoMerlin { inner: digest }
}

impl<D> DigestTranscript for PseudoMerlin<D>
where
    D: Digest,
    <D as Digest>::OutputSize: IsGreaterOrEqual<U32, Output = B1>,
{
    #[inline]
    fn new() -> Self {
        Self {
            inner: <D as Digest>::new(),
        }
    }

    #[inline]
    fn append_bytes(&mut self, context: &'static [u8], data: impl AsRef<[u8]>) {
        // This is meant to closely mimic merlin's STROBE updates
        // https://merlin.cool/transcript/ops.html#appending-messages
        self.inner.update((context.len() as u32).to_le_bytes());
        self.inner.update(context);
        let data = data.as_ref();
        self.inner.update((data.len() as u32).to_le_bytes());
        self.inner.update(data);
    }

    #[inline]
    fn extract_digest(self, output: &mut [u8; 32]) {
        let result = self.inner.finalize();
        output.copy_from_slice(&result[..32]);
    }
}
