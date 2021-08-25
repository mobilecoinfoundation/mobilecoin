// Copyright (c) 2018-2021 The MobileCoin Foundation

#[derive(Debug)]
pub enum TestClientError {
    TxTimeout,
    SubmittedTxTimeout,
    DoubleSpend,
    ClientError(fog_sample_paykit::Error),
}

impl From<fog_sample_paykit::Error> for TestClientError {
    fn from(src: fog_sample_paykit::Error) -> Self {
        TestClientError::ClientError(src)
    }
}
