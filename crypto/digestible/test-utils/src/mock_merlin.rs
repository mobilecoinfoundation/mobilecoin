use mc_crypto_digestible::DigestTranscript;
use std::vec::Vec;

// This is a mock of merlin, which doesn't hash anything, but captures
// the inputs to calls to "append_bytes", so that we can inspect them,
// write tests against them, etc.
#[derive(Default, Clone, Debug)]
pub struct MockMerlin {
    pub append_bytes_calls: Vec<(Vec<u8>, Vec<u8>)>,
}

impl DigestTranscript for MockMerlin {
    fn new() -> Self {
        Default::default()
    }
    fn append_bytes(&mut self, context: &'static [u8], data: impl AsRef<[u8]>) {
        self.append_bytes_calls
            .push((context.to_vec(), data.as_ref().to_vec()));
    }
    fn extract_digest(self, _output: &mut [u8; 32]) {
        panic!("mock doesn't implement extract_digest")
    }
}
