// Copyright (c) 2018-2023 The MobileCoin Foundation

use displaydoc::Display;

#[derive(Clone, Debug, Display)]
pub enum Error {
    /// Not found
    NotFound,

    /// LedgerDb: {0}
    LedgerDb(mc_ledger_db::Error),
}

impl From<mc_ledger_db::Error> for Error {
    fn from(err: mc_ledger_db::Error) -> Self {
        match err {
            mc_ledger_db::Error::NotFound => Self::NotFound,
            _ => Self::LedgerDb(err),
        }
    }
}
