// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_fog_sample_paykit::Error as SamplePaykitError;

#[derive(Debug)]
pub enum TestClientError {
    TxTimeout,
    SubmittedTxTimeout,
    DoubleSpend,
    ClientError(SamplePaykitError),
}

impl From<SamplePaykitError> for TestClientError {
    fn from(src: SamplePaykitError) -> Self {
        TestClientError::ClientError(src)
    }
}
