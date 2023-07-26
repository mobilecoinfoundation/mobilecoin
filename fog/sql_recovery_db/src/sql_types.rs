// Copyright (c) 2018-2022 The MobileCoin Foundation

use diesel::{
    deserialize::{self, FromSql},
    pg::{Pg, PgValue},
    serialize::{self, Output, ToSql},
};
use diesel_derive_enum::DbEnum;
use mc_crypto_keys::CompressedRistrettoPublic;
use std::{fmt, ops::Deref};

#[derive(Debug, PartialEq, DbEnum)]
#[DieselType = "User_event_type"]
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

impl FromSql<diesel::sql_types::Binary, Pg> for SqlCompressedRistrettoPublic {
    fn from_sql(value: PgValue) -> deserialize::Result<Self> {
        let vec = <Vec<u8> as FromSql<diesel::sql_types::Binary, Pg>>::from_sql(value)?;
        if vec.len() != 32 {
            return Err("SqlCompressedRistrettoPublic: Invalid array
        length"
                .into());
        }

        let mut key = [0; 32];
        key.copy_from_slice(&vec);

        match CompressedRistrettoPublic::try_from(&key) {
            Ok(key) => Ok(SqlCompressedRistrettoPublic(key)),
            Err(e) => Err(format!("Key error: {e:?}").into()),
        }
    }
}

impl ToSql<diesel::sql_types::Binary, Pg> for SqlCompressedRistrettoPublic {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        <Vec<u8> as ToSql<diesel::sql_types::Binary, Pg>>::to_sql(
            &self.0.as_bytes().to_vec(),
            &mut out.reborrow(),
        )
    }
}
