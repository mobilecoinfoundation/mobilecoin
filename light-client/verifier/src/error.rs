use mc_api::ConversionError;
use mc_transaction_core::tx::TxOut;
pub enum VerifierError {
    InvalidBlock(ConversionError),
    MissingBlockMetadata,
    MissingBlockSignature,
    NoValidBlocks,
    QuorumNotReached,
    TxosNotFoundInBlock(Vec<TxOut>),
}
