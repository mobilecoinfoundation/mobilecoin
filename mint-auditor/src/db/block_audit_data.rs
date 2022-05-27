use super::Conn;
use crate::error::Error;
use diesel::{dsl::max, prelude::*};
use mc_transaction_core::BlockIndex;

pub use super::models::BlockAuditData;

/// Trait for providing convenience functions for interacting with the
/// [BlockAuditData] model/table.
pub trait BlockAuditDataModel {
    /// Get block audit data for a given block index.
    fn get(conn: &Conn, block_index: BlockIndex) -> Result<BlockAuditData, Error>;

    /// Store block audit data.
    fn set(&self, conn: &Conn) -> Result<(), Error>;

    /// Get the last synced block index.
    fn last_synced_block_index(conn: &Conn) -> Result<Option<BlockIndex>, Error>;
    /// Get the audit data for the last synced block.
    fn last_block_audit_data(conn: &Conn) -> Result<Option<BlockAuditData>, Error>;
}

impl BlockAuditDataModel for BlockAuditData {
    fn get(conn: &Conn, block_index: BlockIndex) -> Result<BlockAuditData, Error> {
        use super::schema::block_audit_data::dsl;
        Ok(dsl::block_audit_data
            .select((dsl::block_index,))
            .filter(dsl::block_index.eq(block_index as i64))
            .get_result::<BlockAuditData>(conn)?)
    }

    fn set(&self, conn: &Conn) -> Result<(), Error> {
        use super::schema::block_audit_data::dsl::block_audit_data;
        diesel::replace_into(block_audit_data)
            .values(self)
            .execute(conn)?;

        Ok(())
    }

    fn last_synced_block_index(conn: &Conn) -> Result<Option<BlockIndex>, Error> {
        use super::schema::block_audit_data::dsl::{block_audit_data, block_index};
        Ok(block_audit_data
            .select(max(block_index))
            .first::<Option<i64>>(conn)?
            .map(|val| val as BlockIndex))
    }

    fn last_block_audit_data(conn: &Conn) -> Result<Option<BlockAuditData>, Error> {
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
