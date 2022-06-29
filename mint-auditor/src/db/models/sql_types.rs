// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::gnosis::{EthAddr, EthTxHash};
use diesel::{
    backend::Backend,
    deserialize::{self, FromSql},
    serialize::{self, Output, ToSql},
};
use serde::{Deserialize, Serialize};
use std::{fmt, io::Write, ops::Deref, str::FromStr};

/// Diesel wrapper for [EthAddr].
#[derive(
    AsExpression,
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    FromSqlRow,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[sql_type = "diesel::sql_types::Text"]
#[serde(transparent)]
pub struct SqlEthAddr(EthAddr);

impl Deref for SqlEthAddr {
    type Target = EthAddr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<EthAddr> for SqlEthAddr {
    fn from(src: EthAddr) -> Self {
        Self(src)
    }
}

impl From<&EthAddr> for SqlEthAddr {
    fn from(src: &EthAddr) -> Self {
        Self(src.clone())
    }
}

impl fmt::Display for SqlEthAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<DB: Backend> ToSql<diesel::sql_types::Text, DB> for SqlEthAddr {
    fn to_sql<W: Write>(&self, out: &mut Output<W, DB>) -> serialize::Result {
        <String as ToSql<diesel::sql_types::Text, DB>>::to_sql(&self.0.to_string(), out)
    }
}

impl<DB> FromSql<diesel::sql_types::Text, DB> for SqlEthAddr
where
    DB: Backend,
    String: FromSql<diesel::sql_types::Text, DB>,
{
    fn from_sql(src: Option<&DB::RawValue>) -> deserialize::Result<Self> {
        let str = String::from_sql(src)?;
        Ok(SqlEthAddr(
            EthAddr::from_str(&str).map_err(|e| e.to_string())?,
        ))
    }
}

/// Diesel wrapper for [EthTxHash].
#[derive(
    AsExpression,
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    FromSqlRow,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[sql_type = "diesel::sql_types::Text"]
#[serde(transparent)]
pub struct SqlEthTxHash(EthTxHash);

impl Deref for SqlEthTxHash {
    type Target = EthTxHash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<EthTxHash> for SqlEthTxHash {
    fn from(src: EthTxHash) -> Self {
        Self(src)
    }
}

impl From<&EthTxHash> for SqlEthTxHash {
    fn from(src: &EthTxHash) -> Self {
        Self(*src)
    }
}

impl fmt::Display for SqlEthTxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<DB: Backend> ToSql<diesel::sql_types::Text, DB> for SqlEthTxHash {
    fn to_sql<W: Write>(&self, out: &mut Output<W, DB>) -> serialize::Result {
        <String as ToSql<diesel::sql_types::Text, DB>>::to_sql(&self.0.to_string(), out)
    }
}

impl<DB> FromSql<diesel::sql_types::Text, DB> for SqlEthTxHash
where
    DB: Backend,
    String: FromSql<diesel::sql_types::Text, DB>,
{
    fn from_sql(src: Option<&DB::RawValue>) -> deserialize::Result<Self> {
        let str = String::from_sql(src)?;
        Ok(SqlEthTxHash(
            EthTxHash::from_str(&str).map_err(|e| e.to_string())?,
        ))
    }
}
