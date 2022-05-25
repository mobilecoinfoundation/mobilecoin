use super::Conn;
use crate::error::Error;
use diesel::prelude::*;

pub use super::models::Counters;

pub trait CountersModel {
    /// Get all counters.
    fn get(conn: &Conn) -> Result<Counters, Error>;

    /// Set all counters.
    fn set(&self, conn: &Conn) -> Result<(), Error>;
}

impl CountersModel for Counters {
    fn get(conn: &Conn) -> Result<Counters, Error> {
        use super::schema::counters::dsl::counters;
        match counters.get_result::<Counters>(conn) {
            Ok(obj) => Ok(obj),
            Err(diesel::result::Error::NotFound) => Ok(Counters::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, conn: &Conn) -> Result<(), Error> {
        use super::schema::counters::dsl::counters;

        diesel::replace_into(counters).values(self).execute(conn)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::TestDbContext;
    use mc_common::logger::{test_with_logger, Logger};

    #[test_with_logger]
    fn counters_sanity_test(logger: Logger) {
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());

        let mut counters = Counters::get(&mint_auditor_db.get_conn().unwrap()).unwrap();
        assert_eq!(counters, Counters::default());

        counters.num_blocks_synced = 123;
        counters.set(&mint_auditor_db.get_conn().unwrap()).unwrap();
        assert_eq!(
            Counters::get(&mint_auditor_db.get_conn().unwrap()).unwrap(),
            counters
        );

        counters.num_blocks_synced = 1234;
        counters.num_burns_exceeding_balance = 5;
        counters.set(&mint_auditor_db.get_conn().unwrap()).unwrap();
        assert_eq!(
            Counters::get(&mint_auditor_db.get_conn().unwrap()).unwrap(),
            counters
        );
    }
}
