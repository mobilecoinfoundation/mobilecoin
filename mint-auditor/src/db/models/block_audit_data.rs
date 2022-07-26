// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{schema::block_audit_data, Conn},
    Error,
};
use diesel::{dsl::max, prelude::*};
use mc_blockchain_types::BlockIndex;
use serde::{Deserialize, Serialize};

/// Diesel model for the `block_audit_data` table.
/// This stores audit data for a specific block index.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize)]
#[table_name = "block_audit_data"]
pub struct BlockAuditData {
    /// Block index.
    block_index: i64,
}

impl BlockAuditData {
    /// Construct a new [BlockAuditData] object.
    pub fn new(block_index: BlockIndex) -> Self {
        Self {
            block_index: block_index as i64,
        }
    }
    /// Get block index.
    pub fn block_index(&self) -> u64 {
        self.block_index as u64
    }

    /// Get block audit data for a given block index.
    pub fn get(conn: &Conn, block_index: BlockIndex) -> Result<Self, Error> {
        Ok(block_audit_data::table
            .select((block_audit_data::block_index,))
            .filter(block_audit_data::block_index.eq(block_index as i64))
            .get_result(conn)?)
    }

    /// Store block audit data.
    pub fn set(&self, conn: &Conn) -> Result<(), Error> {
        diesel::replace_into(block_audit_data::table)
            .values(self)
            .execute(conn)?;

        Ok(())
    }

    /// Get the last synced block index.
    pub fn last_synced_block_index(conn: &Conn) -> Result<Option<BlockIndex>, Error> {
        Ok(block_audit_data::table
            .select(max(block_audit_data::block_index))
            .first::<Option<i64>>(conn)?
            .map(|val| val as BlockIndex))
    }

    /// Get the audit data for the last synced block.
    pub fn last_block_audit_data(conn: &Conn) -> Result<Option<BlockAuditData>, Error> {
        Self::last_synced_block_index(conn)?
            .map(|block_index| Self::get(conn, block_index))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::TestDbContext;
    use mc_common::logger::{test_with_logger, Logger};

    #[test_with_logger]
    fn last_synced_block_index_works(logger: Logger) {
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());

        assert_eq!(
            BlockAuditData::last_synced_block_index(&mint_auditor_db.get_conn().unwrap()).unwrap(),
            None
        );

        BlockAuditData { block_index: 5 }
            .set(&mint_auditor_db.get_conn().unwrap())
            .unwrap();
        assert_eq!(
            BlockAuditData::last_synced_block_index(&mint_auditor_db.get_conn().unwrap()).unwrap(),
            Some(5)
        );

        BlockAuditData { block_index: 3 }
            .set(&mint_auditor_db.get_conn().unwrap())
            .unwrap();
        assert_eq!(
            BlockAuditData::last_synced_block_index(&mint_auditor_db.get_conn().unwrap()).unwrap(),
            Some(5)
        );

        BlockAuditData { block_index: 6 }
            .set(&mint_auditor_db.get_conn().unwrap())
            .unwrap();
        assert_eq!(
            BlockAuditData::last_synced_block_index(&mint_auditor_db.get_conn().unwrap()).unwrap(),
            Some(6)
        );
    }
}
