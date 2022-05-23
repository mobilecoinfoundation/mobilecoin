// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::BlockMetadataContents;
use mc_crypto_digestible_signature::{DigestibleSigner, DigestibleVerifier};
use mc_crypto_keys::{
    Ed25519Pair, Ed25519Public, Ed25519Signature, Signature as SignatureTrait, SignatureError,
};

pub fn block_metadata_context() -> &'static [u8] {
    b"block_metadata"
}

pub trait MetadataSigner: DigestibleSigner<Self::Signature, BlockMetadataContents> {
    type Signature: SignatureTrait;

    fn sign_metadata(
        &self,
        contents: &BlockMetadataContents,
    ) -> Result<Self::Signature, SignatureError> {
        self.try_sign_digestible(block_metadata_context(), contents)
    }
}

impl MetadataSigner for Ed25519Pair {
    type Signature = Ed25519Signature;
}

pub trait MetadataVerifier: DigestibleVerifier<Self::Signature, BlockMetadataContents> {
    type Signature: SignatureTrait;

    fn verify_metadata(
        &self,
        contents: &BlockMetadataContents,
        signature: &Self::Signature,
    ) -> Result<(), SignatureError> {
        self.verify_digestible(block_metadata_context(), contents, signature)
    }
}

impl MetadataVerifier for Ed25519Public {
    type Signature = Ed25519Signature;
}
