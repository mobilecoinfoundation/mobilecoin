// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Transaction utility method that provides automatic retries.

use crate::db::Conn;
use diesel::Connection;
use std::{thread::sleep, time::Duration};

/// A trait for providing insight on whether an error that happened during a
/// transaction should result in retrying.
pub trait TransactionRetriableError {
    /// Should we retry?
    fn should_retry(&self) -> bool;
}

const BASE_DELAY: Duration = Duration::from_millis(10);
const NUM_RETRIES: u32 = 5;

/// Create a SQLite transaction with exponential retry.
pub fn transaction<T, E, F>(conn: &Conn, f: F) -> Result<T, E>
where
    F: Clone + FnOnce(&Conn) -> Result<T, E>,
    E: From<diesel::result::Error> + TransactionRetriableError,
{
    for i in 0..NUM_RETRIES {
        let f = f.clone();
        let r = conn.transaction::<T, E, _>(|| f(conn));
        match r {
            Ok(r) => return Ok(r),
            Err(e) => {
                if !e.should_retry() || i == (NUM_RETRIES - 1) {
                    return Err(e);
                }
            }
        }

        sleep(BASE_DELAY * 2_u32.pow(i));
    }
    panic!("Should never reach this point.");
}
