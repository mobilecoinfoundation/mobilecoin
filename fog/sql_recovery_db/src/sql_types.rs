// Copyright (c) 2018-2022 The MobileCoin Foundation

use diesel::{
    backend::{Backend, RawValue},
    deserialize::{self, FromSql},
    pg::Pg,
    serialize::{self, Output, ToSql},
    AsExpression, FromSqlRow,
};
use diesel_derive_enum::DbEnum;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_util_repr_bytes::ReprBytes;
use std::{fmt, ops::Deref};

#[derive(Debug, PartialEq, DbEnum)]
#[DieselTypePath = "crate::schema::sql_types::UserEventType"]
pub enum UserEventType {
    NewIngestInvocation,
    DecommissionIngestInvocation,
    MissingBlocks,
}

#[derive(AsExpression, FromSqlRow, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[diesel(sql_type = diesel::sql_types::Binary)]
pub struct SqlCompressedRistrettoPublic(CompressedRistrettoPublic);

impl Deref for SqlCompressedRistrettoPublic {
    type Target = CompressedRistrettoPublic;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<CompressedRistrettoPublic> for SqlCompressedRistrettoPublic {
    fn from(src: CompressedRistrettoPublic) -> Self {
        Self(src)
    }
}

impl From<&CompressedRistrettoPublic> for SqlCompressedRistrettoPublic {
    fn from(src: &CompressedRistrettoPublic) -> Self {
        Self(*src)
    }
}

impl fmt::Display for SqlCompressedRistrettoPublic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<DB: Backend> FromSql<diesel::sql_types::Binary, DB> for SqlCompressedRistrettoPublic
where
    Vec<u8>: FromSql<diesel::sql_types::Binary, DB>,
{
    fn from_sql(bytes: RawValue<'_, DB>) -> deserialize::Result<Self> {
        Self::from_nullable_sql(Some(bytes))
    }

    fn from_nullable_sql(bytes: Option<RawValue<'_, DB>>) -> deserialize::Result<Self> {
        let vec = <Vec<u8> as FromSql<diesel::sql_types::Binary, DB>>::from_nullable_sql(bytes)?;
        if vec.len() != 32 {
            return Err("SqlCompressedRistrettoPublic: Invalid array length".into());
        }

        let mut key = [0; 32];
        key.copy_from_slice(&vec);

        Ok(SqlCompressedRistrettoPublic(
            CompressedRistrettoPublic::from(&key),
        ))
    }
}

impl ToSql<diesel::sql_types::Binary, Pg> for SqlCompressedRistrettoPublic {
    fn to_sql(&self, out: &mut Output<Pg>) -> serialize::Result {
        <Vec<u8> as ToSql<diesel::sql_types::Binary, Pg>>::to_sql(
            &self.0.to_bytes().to_vec(),
            &mut out.reborrow(),
        )
    }
}
