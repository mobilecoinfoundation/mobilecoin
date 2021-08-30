// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Recovery db implementation using a PostgreSQL database backend.

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate diesel_migrations;

pub mod test_utils;

mod error;
mod models;
mod proto_types;
mod schema;
mod sql_types;

use crate::sql_types::{SqlCompressedRistrettoPublic, UserEventType};
use diesel::{
    pg::PgConnection,
    prelude::*,
    r2d2::{ConnectionManager, Pool},
};
use mc_attest_core::VerificationReport;
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_recovery_db_iface::{
    AddBlockDataStatus, FogUserEvent, IngestInvocationId, IngressPublicKeyRecord,
    IngressPublicKeyStatus, RecoveryDb, ReportData, ReportDb,
};
use mc_fog_types::{
    common::BlockRange,
    view::{TxOutSearchResult, TxOutSearchResultCode},
    ETxOutRecord,
};
use mc_transaction_core::Block;
use prost::Message;
use proto_types::ProtoIngestedBlockData;

pub use error::Error;

/// Maximum number of parameters PostgreSQL allows in a single query.
/// The actual limit is 65535. This value is more conservative, resulting on
/// potentially issueing more queries to the server. This is not expected to be
/// an issue.
pub const SQL_MAX_PARAMS: usize = 65000;

/// Maximal number of rows to insert in one batch.
pub const SQL_MAX_ROWS: usize = 5000;

/// SQL-backed recovery database.
#[derive(Clone)]
pub struct SqlRecoveryDb {
    pool: Pool<ConnectionManager<PgConnection>>,
    logger: Logger,
}

impl SqlRecoveryDb {
    /// Create a new instance using a pre-existing connection pool.
    pub fn new(pool: Pool<ConnectionManager<PgConnection>>, logger: Logger) -> Self {
        Self { pool, logger }
    }

    /// Create a new instance using a database URL. This will create a
    /// connection pool of size 1. The benefit of doing this is that the
    /// pool takes care of automatically reconnecting to the database if the
    /// connection dies.
    pub fn new_from_url(database_url: &str, logger: Logger) -> Result<Self, Error> {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = Pool::builder()
            .max_size(1)
            .test_on_check_out(true)
            .build(manager)?;
        Ok(Self::new(pool, logger))
    }

    /// Mark a given ingest invocation as decommissioned.
    fn decommission_ingest_invocation_impl(
        &self,
        conn: &PgConnection,
        ingest_invocation_id: &IngestInvocationId,
    ) -> Result<(), Error> {
        // Mark the ingest invocation as decommissioned.
        diesel::update(
            schema::ingest_invocations::dsl::ingest_invocations
                .filter(schema::ingest_invocations::dsl::id.eq(**ingest_invocation_id)),
        )
        .set((
            schema::ingest_invocations::dsl::decommissioned.eq(true),
            schema::ingest_invocations::dsl::last_active_at.eq(diesel::expression::dsl::now),
        ))
        .execute(conn)?;

        // Write a user event.
        let new_event =
            models::NewUserEvent::decommission_ingest_invocation(**ingest_invocation_id);

        diesel::insert_into(schema::user_events::table)
            .values(&new_event)
            .execute(conn)?;

        Ok(())
    }

    /// Mark a given ingest invocation as still being alive.
    fn update_last_active_at_impl(
        &self,
        conn: &PgConnection,
        ingest_invocation_id: &IngestInvocationId,
    ) -> Result<(), Error> {
        diesel::update(
            schema::ingest_invocations::dsl::ingest_invocations
                .filter(schema::ingest_invocations::dsl::id.eq(**ingest_invocation_id)),
        )
        .set(schema::ingest_invocations::dsl::last_active_at.eq(diesel::expression::dsl::now))
        .execute(conn)?;

        Ok(())
    }

    /// Get missed block ranges.
    fn get_missed_block_ranges_impl(&self, conn: &PgConnection) -> Result<Vec<BlockRange>, Error> {
        let query = schema::user_events::dsl::user_events
            .filter(schema::user_events::dsl::event_type.eq(UserEventType::MissingBlocks))
            .select((
                schema::user_events::dsl::id,
                schema::user_events::dsl::missing_blocks_start,
                schema::user_events::dsl::missing_blocks_end,
            ))
            .order_by(schema::user_events::dsl::id);

        let rows = query.load::<(i64, Option<i64>, Option<i64>)>(conn)?;

        rows.iter()
            .map(|row| match row {
                (_, Some(start_index), Some(end_index)) => {
                    Ok(BlockRange::new(*start_index as u64, *end_index as u64))
                }
                (id, _, _) => Err(Error::UserEventSchemaViolation(
                    *id,
                    "missing start or end block indices",
                )),
            })
            .collect::<Result<Vec<BlockRange>, Error>>()
    }

    fn get_ingress_key_status_impl(
        &self,
        conn: &PgConnection,
        key: &CompressedRistrettoPublic,
    ) -> Result<Option<IngressPublicKeyStatus>, Error> {
        let key_bytes: &[u8] = key.as_ref();
        use schema::ingress_keys::dsl;
        let key_records: Vec<models::IngressKey> = dsl::ingress_keys
            .filter(dsl::ingress_public_key.eq(key_bytes))
            .load(conn)?;

        if key_records.is_empty() {
            Ok(None)
        } else if key_records.len() == 1 {
            Ok(Some(IngressPublicKeyStatus {
                start_block: key_records[0].start_block as u64,
                pubkey_expiry: key_records[0].pubkey_expiry as u64,
                retired: key_records[0].retired,
                lost: key_records[0].lost,
            }))
        } else {
            Err(Error::IngressKeysSchemaViolation(format!(
                "Found multiple entries for key: {:?}",
                key
            )))
        }
    }
}

/// See trait `fog_recovery_db_iface::RecoveryDb` for documentation.
impl RecoveryDb for SqlRecoveryDb {
    type Error = Error;

    fn get_ingress_key_status(
        &self,
        key: &CompressedRistrettoPublic,
    ) -> Result<Option<IngressPublicKeyStatus>, Error> {
        let conn = self.pool.get()?;
        self.get_ingress_key_status_impl(&conn, key)
    }

    fn new_ingress_key(
        &self,
        key: &CompressedRistrettoPublic,
        start_block: u64,
    ) -> Result<bool, Error> {
        let conn = self.pool.get()?;
        let obj = models::NewIngressKey {
            ingress_public_key: (*key).into(),
            start_block: start_block as i64,
            pubkey_expiry: 0,
            retired: false,
            lost: false,
        };

        let inserted_row_count = diesel::insert_into(schema::ingress_keys::table)
            .values(&obj)
            .on_conflict_do_nothing()
            .execute(&conn)?;

        Ok(inserted_row_count > 0)
    }

    fn retire_ingress_key(
        &self,
        key: &CompressedRistrettoPublic,
        set_retired: bool,
    ) -> Result<(), Error> {
        let key_bytes: &[u8] = key.as_ref();

        let conn = self.pool.get()?;
        use schema::ingress_keys::dsl;
        diesel::update(dsl::ingress_keys.filter(dsl::ingress_public_key.eq(key_bytes)))
            .set(dsl::retired.eq(set_retired))
            .execute(&conn)?;
        Ok(())
    }

    fn get_last_scanned_block_index(
        &self,
        key: &CompressedRistrettoPublic,
    ) -> Result<Option<u64>, Error> {
        let key_bytes: &[u8] = key.as_ref();

        let conn = self.pool.get()?;

        use schema::ingested_blocks::dsl;
        let maybe_index: Option<i64> = dsl::ingested_blocks
            .filter(dsl::ingress_public_key.eq(key_bytes))
            .select(diesel::dsl::max(dsl::block_number))
            .first(&conn)?;

        Ok(maybe_index.map(|val| val as u64))
    }

    fn get_ingress_key_records(
        &self,
        start_block_at_least: u64,
    ) -> Result<Vec<IngressPublicKeyRecord>, Error> {
        let conn = self.pool.get()?;

        use schema::ingress_keys::dsl;
        let query = dsl::ingress_keys
            .select((
                dsl::ingress_public_key,
                dsl::start_block,
                dsl::pubkey_expiry,
                dsl::retired,
                dsl::lost,
                diesel::dsl::sql::<diesel::sql_types::BigInt>(
                    "(SELECT MAX(block_number) FROM ingested_blocks WHERE ingress_keys.ingress_public_key = ingested_blocks.ingress_public_key)"
                ).nullable(),

            ))
            .filter(dsl::start_block.ge(start_block_at_least as i64));

        // The list of fields here must match the .select() clause above.
        Ok(query
            .load::<(
                SqlCompressedRistrettoPublic,
                i64,
                i64,
                bool,
                bool,
                Option<i64>,
            )>(&conn)?
            .into_iter()
            .map(
                |(
                    ingress_public_key,
                    start_block,
                    pubkey_expiry,
                    retired,
                    lost,
                    last_scanned_block,
                )| {
                    let status = IngressPublicKeyStatus {
                        start_block: start_block as u64,
                        pubkey_expiry: pubkey_expiry as u64,
                        retired,
                        lost,
                    };

                    IngressPublicKeyRecord {
                        key: *ingress_public_key,
                        status,
                        last_scanned_block: last_scanned_block.map(|v| v as u64),
                    }
                },
            )
            .collect())
    }

    fn new_ingest_invocation(
        &self,
        prev_ingest_invocation_id: Option<IngestInvocationId>,
        ingress_public_key: &CompressedRistrettoPublic,
        egress_public_key: &KexRngPubkey,
        start_block: u64,
    ) -> Result<IngestInvocationId, Error> {
        let conn = self.pool.get()?;
        conn.build_transaction().read_write().run(|| {
            // Optionally decommission old invocation.
            if let Some(prev_ingest_invocation_id) = prev_ingest_invocation_id {
                self.decommission_ingest_invocation_impl(&conn, &prev_ingest_invocation_id)?;
            }

            // Write new invocation.
            let now =
                diesel::select(diesel::dsl::now).get_result::<chrono::NaiveDateTime>(&conn)?;

            let obj = models::NewIngestInvocation {
                ingress_public_key: (*ingress_public_key).into(),
                egress_public_key: egress_public_key.public_key.clone(),
                last_active_at: now,
                start_block: start_block as i64,
                decommissioned: false,
                rng_version: egress_public_key.version as i32,
            };

            let inserted_obj: models::IngestInvocation =
                diesel::insert_into(schema::ingest_invocations::table)
                    .values(&obj)
                    .get_result(&conn)?;

            // Write a user event.
            let new_event = models::NewUserEvent::new_ingest_invocation(inserted_obj.id);

            diesel::insert_into(schema::user_events::table)
                .values(&new_event)
                .execute(&conn)?;

            // Success.
            Ok(IngestInvocationId::from(inserted_obj.id))
        })
    }

    fn get_ingestable_ranges(
        &self,
    ) -> Result<Vec<mc_fog_recovery_db_iface::IngestableRange>, Self::Error> {
        let conn = self.pool.get()?;

        // For each ingest invocation we are aware of get its id, start block, is
        // decommissioned and the max block number it has ingested (if
        // available).
        let query = schema::ingest_invocations::dsl::ingest_invocations
            .select((
                schema::ingest_invocations::dsl::id,
                schema::ingest_invocations::dsl::start_block,
                schema::ingest_invocations::dsl::decommissioned,
                diesel::dsl::sql::<diesel::sql_types::BigInt>(
                    "(SELECT MAX(block_number) FROM ingested_blocks WHERE ingest_invocations.id = ingested_blocks.ingest_invocation_id)"
                ).nullable(),
            ))
            .order_by(schema::ingest_invocations::dsl::id);

        // The list of fields here must match the .select() clause above.
        let data = query.load::<(i64, i64, bool, Option<i64>)>(&conn)?;
        Ok(data
            .into_iter()
            .map(|row| {
                let (ingest_invocation_id, start_block, decommissioned, last_ingested_block) = row;

                mc_fog_recovery_db_iface::IngestableRange {
                    id: IngestInvocationId::from(ingest_invocation_id),
                    start_block: start_block as u64,
                    decommissioned,
                    last_ingested_block: last_ingested_block.map(|v| v as u64),
                }
            })
            .collect())
    }

    /// Decommission a given ingest invocation.
    ///
    /// This should be done when a given ingest enclave goes down or is retired.
    ///
    /// Arguments:
    /// * ingest_invocation_id: The unique ingest invocation id that has been
    ///   retired
    fn decommission_ingest_invocation(
        &self,
        ingest_invocation_id: &IngestInvocationId,
    ) -> Result<(), Self::Error> {
        let conn = self.pool.get()?;

        conn.build_transaction()
            .read_write()
            .run(|| self.decommission_ingest_invocation_impl(&conn, ingest_invocation_id))
    }

    fn add_block_data(
        &self,
        ingest_invocation_id: &IngestInvocationId,
        block: &Block,
        block_signature_timestamp: u64,
        txs: &[mc_fog_types::ETxOutRecord],
    ) -> Result<AddBlockDataStatus, Self::Error> {
        let conn = self.pool.get()?;

        match conn
            .build_transaction()
            .read_write()
            .run(|| -> Result<(), Self::Error> {
                // Get ingress pubkey of this ingest invocation id, which is also stored in the
                // ingested_block record
                //
                // Note: Possibly, we can use an inner-join or something when we would have
                // needed this, and then not have this in the ingest_blocks
                // table? It makes the sql expressions simpler for now, we could
                // delete that column from table later
                let ingress_key_bytes: Vec<u8> = schema::ingest_invocations::table
                    .filter(schema::ingest_invocations::dsl::id.eq(**ingest_invocation_id))
                    .select(schema::ingest_invocations::ingress_public_key)
                    .first(&conn)?;

                // Get bytes of encoded proto ingested block data
                let proto_bytes = {
                    let proto_ingested_block_data = ProtoIngestedBlockData {
                        e_tx_out_records: txs.to_vec(),
                    };
                    let mut bytes =
                        Vec::<u8>::with_capacity(proto_ingested_block_data.encoded_len());
                    proto_ingested_block_data.encode(&mut bytes)?;
                    bytes
                };

                // Add an IngestedBlock record.
                let new_ingested_block = models::NewIngestedBlock {
                    ingress_public_key: ingress_key_bytes,
                    ingest_invocation_id: **ingest_invocation_id,
                    block_number: block.index as i64,
                    cumulative_txo_count: block.cumulative_txo_count as i64,
                    block_signature_timestamp: block_signature_timestamp as i64,
                    proto_ingested_block_data: proto_bytes,
                };

                diesel::insert_into(schema::ingested_blocks::table)
                    .values(&new_ingested_block)
                    .execute(&conn)?;

                // Update last active at.
                self.update_last_active_at_impl(&conn, ingest_invocation_id)?;

                // Success.
                Ok(())
            }) {
            Ok(()) => Ok(AddBlockDataStatus {
                block_already_scanned_with_this_key: false,
            }),
            // If a unique constraint is violated, we return Ok(block_already_scanned: true) instead
            // of an error This makes it a little easier for the caller to access this
            // information without making custom traits for interrogating generic
            // errors.
            Err(Self::Error::Orm(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ))) => Ok(AddBlockDataStatus {
                block_already_scanned_with_this_key: true,
            }),
            Err(err) => Err(err),
        }
    }

    fn report_lost_ingress_key(
        &self,
        lost_ingress_key: CompressedRistrettoPublic,
    ) -> Result<(), Self::Error> {
        let conn = self.pool.get()?;

        conn.build_transaction().read_write().run(|| {
            // Find the ingress key and update it to be marked lost
            let key_bytes: &[u8] = lost_ingress_key.as_ref();
            use schema::ingress_keys::dsl;
            let key_records: Vec<models::IngressKey> =
                diesel::update(dsl::ingress_keys.filter(dsl::ingress_public_key.eq(key_bytes)))
                    .set(dsl::lost.eq(true))
                    .get_results(&conn)?;

            // Compute a missed block range based on looking at the key status,
            // which is correct if no blocks have actually been scanned using the key.
            let mut missed_block_range = if key_records.is_empty() {
                return Err(Error::MissingIngressKey(lost_ingress_key));
            } else if key_records.len() == 1 {
                BlockRange {
                    start_block: key_records[0].start_block as u64,
                    end_block: key_records[0].pubkey_expiry as u64,
                }
            } else {
                return Err(Error::IngressKeysSchemaViolation(format!(
                    "Found multiple entries for key: {:?}",
                    lost_ingress_key
                )));
            };

            // Find the last scanned block index (if any block has been scanned with this
            // key)
            let maybe_block_index: Option<i64> = {
                use schema::ingested_blocks::dsl;
                dsl::ingested_blocks
                    .filter(dsl::ingress_public_key.eq(key_bytes))
                    .select(diesel::dsl::max(dsl::block_number))
                    .first(&conn)?
            };

            if let Some(block_index) = maybe_block_index {
                let block_index = block_index as u64;
                if block_index + 1 >= missed_block_range.end_block {
                    // There aren't actually any blocks that need to be scanned, so we are done
                    // without creating a user event.
                    return Ok(());
                }
                // If we did actually scan some blocks, then report a smaller range
                if block_index + 1 > missed_block_range.start_block {
                    missed_block_range.start_block = block_index + 1;
                }
            }

            // If the missed block range is invalid (empty), we don't have to add it.
            // This can happen if the ingress key was never actually published to the report
            // server, and then pubkey_expiry is zero.
            if !missed_block_range.is_valid() {
                return Ok(());
            }

            // Add new range.
            let new_event = models::NewUserEvent::missing_blocks(&missed_block_range);

            diesel::insert_into(schema::user_events::table)
                .values(&new_event)
                .execute(&conn)?;

            Ok(())
        })
    }

    fn get_missed_block_ranges(&self) -> Result<Vec<BlockRange>, Self::Error> {
        let conn = self.pool.get()?;
        self.get_missed_block_ranges_impl(&conn)
    }

    fn search_user_events(
        &self,
        start_from_user_event_id: i64,
    ) -> Result<(Vec<FogUserEvent>, i64), Self::Error> {
        // Early return if start_from_user_event_id is max
        if start_from_user_event_id == i64::MAX {
            return Ok((Default::default(), i64::MAX));
        }

        let conn = self.pool.get()?;
        let mut events: Vec<(i64, FogUserEvent)> = Vec::new();

        // Collect all events of interest
        let query = schema::user_events::dsl::user_events
            // Left-join ingest invocation information, needed for NewRngRecord events
            .left_join(
                schema::ingest_invocations::dsl::ingest_invocations.on(
                    schema::user_events::dsl::new_ingest_invocation_id.eq(
                        schema::ingest_invocations::dsl::id.nullable()
                    )
                )
            )

            // Filtered by the subset of ids we are exploring
            // NOTE: sql auto increment columns start from 1, so "start_from_user_event_id = 0"
            // will capture everything
            .filter(schema::user_events::dsl::id.gt(start_from_user_event_id))
            // Get only the fields that we need
            .select((
                // Fields for every event type
                schema::user_events::dsl::id,
                schema::user_events::dsl::event_type,
                // Fields for NewIngestInvocation events
                schema::ingest_invocations::dsl::id.nullable(),
                schema::ingest_invocations::dsl::egress_public_key.nullable(),
                schema::ingest_invocations::dsl::rng_version.nullable(),
                schema::ingest_invocations::dsl::start_block.nullable(),
                // Fields for DecommissionIngestInvocation
                schema::user_events::dsl::decommission_ingest_invocation_id,
                diesel::dsl::sql::<diesel::sql_types::BigInt>("(SELECT COALESCE(MAX(block_number), 0) FROM ingested_blocks WHERE user_events.event_type = 'decommission_ingest_invocation' AND ingested_blocks.ingest_invocation_id = user_events.decommission_ingest_invocation_id)"),
                // Fields for MissingBlocks events
                schema::user_events::dsl::missing_blocks_start,
                schema::user_events::dsl::missing_blocks_end,
            ));

        // The list of fields here must match the .select() clause above.
        let data = query.load::<(
            // For all event types
            i64,           // user_events.id
            UserEventType, // user_events.event_type
            // For NewRngRecord events
            Option<i64>,     // rng_record.ingest_invocation_id
            Option<Vec<u8>>, // rng_record.egress_public_key
            Option<i32>,     // rng_record.rng_version
            Option<i64>,     // rng_record.start_block
            // For DecommissionIngestInvocation events
            Option<i64>, // ingest_invocations.id
            i64,         // MAX(ingested_blocks.block_number)
            // For MissingBlocks events
            Option<i64>, // user_events.missing_blocks_start
            Option<i64>, // user_events.missing_blocks_end
        )>(&conn)?;

        // If no events are found, return start_from_user_event_id and not 0
        let mut max_user_event_id = start_from_user_event_id;
        for row in data.into_iter() {
            // The list of fields here must match the .select() clause above.
            let (
                user_event_id,
                user_event_type,
                rng_record_ingest_invocation_id,
                rng_record_egress_public_key,
                rng_record_rng_version,
                rng_record_start_block,
                decommission_ingest_invocation_id,
                decommission_ingest_invocation_max_block,
                missing_blocks_start,
                missing_blocks_end,
            ) = row;

            // Update running max
            max_user_event_id = core::cmp::max(max_user_event_id, user_event_id);

            events.push((
                user_event_id,
                match user_event_type {
                    UserEventType::NewIngestInvocation => {
                        FogUserEvent::NewRngRecord(mc_fog_types::view::RngRecord {
                            ingest_invocation_id: rng_record_ingest_invocation_id.ok_or(
                                Error::UserEventSchemaViolation(
                                    user_event_id,
                                    "missing rng_record_ingest_invocation_id",
                                ),
                            )?,
                            pubkey: mc_fog_types::view::KexRngPubkey {
                                public_key: rng_record_egress_public_key.ok_or(
                                    Error::UserEventSchemaViolation(
                                        user_event_id,
                                        "missing rng_record_egress_public_key",
                                    ),
                                )?,
                                version: rng_record_rng_version.ok_or(
                                    Error::UserEventSchemaViolation(
                                        user_event_id,
                                        "missing rng_record_rng_version",
                                    ),
                                )? as u32,
                            },
                            start_block: rng_record_start_block.ok_or(
                                Error::UserEventSchemaViolation(
                                    user_event_id,
                                    "missing rng_record_start_block",
                                ),
                            )? as u64,
                        })
                    }
                    UserEventType::DecommissionIngestInvocation => {
                        FogUserEvent::DecommissionIngestInvocation(
                            mc_fog_types::view::DecommissionedIngestInvocation {
                                ingest_invocation_id: decommission_ingest_invocation_id.ok_or(
                                    Error::UserEventSchemaViolation(
                                        user_event_id,
                                        "missing decommission_ingest_invocation_id",
                                    ),
                                )?,
                                last_ingested_block: decommission_ingest_invocation_max_block
                                    as u64,
                            },
                        )
                    }
                    UserEventType::MissingBlocks => {
                        FogUserEvent::MissingBlocks(mc_fog_types::common::BlockRange {
                            start_block: missing_blocks_start.ok_or(
                                Error::UserEventSchemaViolation(
                                    user_event_id,
                                    "missing missing_blocks_start",
                                ),
                            )? as u64,
                            end_block: missing_blocks_end.ok_or(Error::UserEventSchemaViolation(
                                user_event_id,
                                "missing missing_blocks_end",
                            ))? as u64,
                        })
                    }
                },
            ));
        }

        // Ensure events are properly sorted.
        events.sort_by_key(|(id, _event)| *id);

        // Return.
        Ok((
            events.into_iter().map(|(_event_id, event)| event).collect(),
            max_user_event_id,
        ))
    }

    /// Get any TxOutSearchResults corresponding to given search keys.
    /// Nonzero start_block can be provided as an optimization opportunity.
    ///
    /// Note: This is still supported for some tests, but it is VERY SLOW.
    /// We no longer have an index for ETxOutRecords by search key in the SQL
    /// directly. This should not be used except in tests.
    ///
    /// Arguments:
    /// * start_block: A lower bound on where we will search. This can often be
    ///   provided by the user in order to limit the scope of the search and
    ///   reduce load on the servers.
    /// * search_keys: A list of fog tx_out search keys to search for.
    ///
    /// Returns:
    /// * Exactly one TxOutSearchResult object for every search key, or an
    ///   internal database error description.
    fn get_tx_outs(
        &self,
        start_block: u64,
        search_keys: &[Vec<u8>],
    ) -> Result<Vec<TxOutSearchResult>, Self::Error> {
        let conn = self.pool.get()?;

        let query = schema::ingested_blocks::dsl::ingested_blocks
            .filter(schema::ingested_blocks::dsl::block_number.ge(start_block as i64))
            .select(schema::ingested_blocks::dsl::proto_ingested_block_data);

        let mut search_key_to_payload = HashMap::<Vec<u8>, Vec<u8>>::default();
        for proto_bytes in query.load::<Vec<u8>>(&conn)? {
            let proto = ProtoIngestedBlockData::decode(&*proto_bytes)?;
            for e_tx_out_record in proto.e_tx_out_records {
                search_key_to_payload.insert(e_tx_out_record.search_key, e_tx_out_record.payload);
            }
        }

        let mut results = Vec::new();
        for search_key in search_keys {
            results.push(match search_key_to_payload.get(search_key) {
                Some(payload) => TxOutSearchResult {
                    search_key: search_key.clone(),
                    result_code: TxOutSearchResultCode::Found as u32,
                    ciphertext: payload.clone(),
                },

                None => TxOutSearchResult {
                    search_key: search_key.clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: Default::default(),
                },
            });
        }

        Ok(results)
    }

    /// Mark a given ingest invocation as still being alive.
    fn update_last_active_at(
        &self,
        ingest_invocation_id: &IngestInvocationId,
    ) -> Result<(), Self::Error> {
        let conn = self.pool.get()?;
        self.update_last_active_at_impl(&conn, ingest_invocation_id)
    }

    /// Get any ETxOutRecords produced by a given ingress key for a given
    /// block index.
    ///
    /// Arguments:
    /// * ingress_key: The ingress key we need ETxOutRecords from
    /// * block_index: The block we need ETxOutRecords from
    ///
    /// Returns:
    /// * The ETxOutRecord's from when this block was added, or None if the
    ///   block doesn't exist yet or, an error
    fn get_tx_outs_by_block_and_key(
        &self,
        ingress_key: CompressedRistrettoPublic,
        block_index: u64,
    ) -> Result<Option<Vec<ETxOutRecord>>, Self::Error> {
        let conn = self.pool.get()?;

        let key_bytes: &[u8] = ingress_key.as_ref();
        let query = schema::ingested_blocks::dsl::ingested_blocks
            .filter(schema::ingested_blocks::dsl::ingress_public_key.eq(key_bytes))
            .filter(schema::ingested_blocks::dsl::block_number.eq(block_index as i64))
            .select(schema::ingested_blocks::dsl::proto_ingested_block_data);

        // The result of load should be 0 or 1, since there is a database constraint
        // around ingress keys and block indices
        let protos: Vec<Vec<u8>> = query.load::<Vec<u8>>(&conn)?;

        if protos.is_empty() {
            Ok(None)
        } else if protos.len() == 1 {
            let proto = ProtoIngestedBlockData::decode(&*protos[0])?;
            Ok(Some(proto.e_tx_out_records))
        } else {
            Err(Error::IngestedBlockSchemaViolation(format!("Found {} different entries for ingress_key {:?} and block_index {}, which goes against the constraint", protos.len(), ingress_key, block_index)))
        }
    }

    /// Get iid that produced data for given ingress key and a given block
    /// index.
    fn get_invocation_id_by_block_and_key(
        &self,
        ingress_key: CompressedRistrettoPublic,
        block_index: u64,
    ) -> Result<Option<IngestInvocationId>, Self::Error> {
        let conn = self.pool.get()?;

        let key_bytes: &[u8] = ingress_key.as_ref();
        let query = schema::ingested_blocks::dsl::ingested_blocks
            .filter(schema::ingested_blocks::dsl::ingress_public_key.eq(key_bytes))
            .filter(schema::ingested_blocks::dsl::block_number.eq(block_index as i64))
            .select(schema::ingested_blocks::dsl::ingest_invocation_id);

        // The result of load should be 0 or 1, since there is a database constraint
        // around ingress keys and block indices
        let iids: Vec<i64> = query.load::<i64>(&conn)?;

        if iids.is_empty() {
            Ok(None)
        } else if iids.len() == 1 {
            Ok(Some(iids[0].into()))
        } else {
            Err(Error::IngestedBlockSchemaViolation(format!("Found {} different entries for ingress_key {:?} and block_index {}, which goes against the constraint", iids.len(), ingress_key, block_index)))
        }
    }

    /// Get the cumulative txo count for a given block number.
    ///
    /// Arguments:
    /// * block_index: The block we need cumulative_txo_count for.
    ///
    /// Returns:
    /// * Some(cumulative_txo_count) if the block was found in the database,
    ///   None if it wasn't, or
    /// an error if the query failed.
    fn get_cumulative_txo_count_for_block(
        &self,
        block_index: u64,
    ) -> Result<Option<u64>, Self::Error> {
        let conn = self.pool.get()?;

        let query = schema::ingested_blocks::dsl::ingested_blocks
            .filter(schema::ingested_blocks::dsl::block_number.eq(block_index as i64))
            .select(schema::ingested_blocks::dsl::cumulative_txo_count);

        let data = query.load::<i64>(&conn)?;
        if data.is_empty() {
            Ok(None)
        } else {
            let cumulative_txo_count = data[0];
            if data.iter().all(|val| *val == cumulative_txo_count) {
                Ok(Some(cumulative_txo_count as u64))
            } else {
                Err(Error::IngestedBlockSchemaViolation(format!(
                    "Found multiple cumulative_txo_count values for block {}: {:?}",
                    block_index, data
                )))
            }
        }
    }

    /// Get the block signature timestamp for a given block number.
    /// Note that it is unspecified which timestamp we use if there are multiple
    /// timestamps.
    ///
    /// Arguments:
    /// * block_index: The block we need timestamp for.
    ///
    /// Returns:
    /// * Some(cumulative_txo_count) if the block was found in the database,
    ///   None if it wasn't, or
    /// an error if the query failed.
    fn get_block_signature_timestamp_for_block(
        &self,
        block_index: u64,
    ) -> Result<Option<u64>, Self::Error> {
        let conn = self.pool.get()?;

        let query = schema::ingested_blocks::dsl::ingested_blocks
            .filter(schema::ingested_blocks::dsl::block_number.eq(block_index as i64))
            .select(schema::ingested_blocks::dsl::block_signature_timestamp);

        let data = query.load::<i64>(&conn)?;
        Ok(data.first().map(|val| *val as u64))
    }

    /// Get the highest block index for which we have any data at all.
    fn get_highest_known_block_index(&self) -> Result<Option<u64>, Self::Error> {
        let conn = self.pool.get()?;

        Ok(schema::ingested_blocks::dsl::ingested_blocks
            .select(diesel::dsl::max(schema::ingested_blocks::dsl::block_number))
            .first::<Option<i64>>(&conn)?
            .map(|val| val as u64))
    }
}

/// See trait `fog_recovery_db_iface::ReportDb` for documentation.
impl ReportDb for SqlRecoveryDb {
    type Error = Error;

    fn get_all_reports(&self) -> Result<Vec<(String, ReportData)>, Self::Error> {
        let conn = self.pool.get()?;

        let query = schema::reports::dsl::reports
            .select((
                schema::reports::dsl::ingest_invocation_id,
                schema::reports::dsl::fog_report_id,
                schema::reports::dsl::report,
                schema::reports::dsl::pubkey_expiry,
            ))
            .order_by(schema::reports::dsl::id);

        query
            .load::<(Option<i64>, String, Vec<u8>, i64)>(&conn)?
            .into_iter()
            .map(|(ingest_invocation_id, report_id, report, pubkey_expiry)| {
                let report = VerificationReport::decode(&*report)?;
                Ok((
                    report_id,
                    ReportData {
                        ingest_invocation_id: ingest_invocation_id.map(IngestInvocationId::from),
                        report,
                        pubkey_expiry: pubkey_expiry as u64,
                    },
                ))
            })
            .collect()
    }

    /// Set report data associated with a given report id.
    fn set_report(
        &self,
        ingress_key: &CompressedRistrettoPublic,
        report_id: &str,
        data: &ReportData,
    ) -> Result<IngressPublicKeyStatus, Self::Error> {
        let conn = self.pool.get()?;

        conn.build_transaction().read_write().run(
            || -> Result<IngressPublicKeyStatus, Self::Error> {
                // First, try to update the pubkey_expiry value on this ingress key, only
                // allowing it to increase, and only if it is not retired
                let result: IngressPublicKeyStatus = {
                    let key_bytes: &[u8] = ingress_key.as_ref();

                    use schema::ingress_keys::dsl;
                    let key_records: Vec<models::IngressKey> = diesel::update(
                        dsl::ingress_keys
                            .filter(dsl::ingress_public_key.eq(key_bytes))
                            .filter(dsl::retired.eq(false))
                            .filter(dsl::pubkey_expiry.lt(data.pubkey_expiry as i64)),
                    )
                    .set(dsl::pubkey_expiry.eq(data.pubkey_expiry as i64))
                    .get_results(&conn)?;

                    if key_records.is_empty() {
                        // If the result is empty, the key might not exist, or it might have had a
                        // larger pubkey expiry (because this server is behind),
                        // so we need to make another query to find which is the case
                        log::info!(self.logger, "update was a no-op");
                        let maybe_key_status =
                            self.get_ingress_key_status_impl(&conn, ingress_key)?;
                        log::info!(self.logger, "check ingress key passed");
                        maybe_key_status.ok_or(Error::MissingIngressKey(*ingress_key))?
                    } else if key_records.len() > 1 {
                        return Err(Error::IngressKeysSchemaViolation(format!(
                            "Found multiple entries for key: {:?}",
                            *ingress_key
                        )));
                    } else {
                        IngressPublicKeyStatus {
                            start_block: key_records[0].start_block as u64,
                            pubkey_expiry: key_records[0].pubkey_expiry as u64,
                            retired: key_records[0].retired,
                            lost: key_records[0].lost,
                        }
                    }
                };

                log::info!(self.logger, "Got status for key: {:?}", result);
                if result.retired {
                    log::info!(self.logger, "Cannot publish key because it is retired");
                    return Ok(result);
                }

                let mut report_bytes = Vec::with_capacity(data.report.encoded_len());
                data.report.encode(&mut report_bytes)?;
                let report = models::NewReport {
                    ingress_public_key: ingress_key.as_ref(),
                    ingest_invocation_id: data.ingest_invocation_id.map(i64::from),
                    fog_report_id: report_id,
                    report: report_bytes.as_slice(),
                    pubkey_expiry: data.pubkey_expiry as i64,
                };

                diesel::insert_into(schema::reports::dsl::reports)
                    .values(&report)
                    .on_conflict(schema::reports::dsl::fog_report_id)
                    .do_update()
                    .set((
                        schema::reports::dsl::ingress_public_key.eq(report.ingress_public_key),
                        schema::reports::dsl::ingest_invocation_id.eq(report.ingest_invocation_id),
                        schema::reports::dsl::report.eq(report_bytes.clone()),
                        schema::reports::dsl::pubkey_expiry.eq(report.pubkey_expiry),
                    ))
                    .execute(&conn)?;
                Ok(result)
            },
        )
    }

    /// Remove report data associated with a given report id.
    fn remove_report(&self, report_id: &str) -> Result<(), Self::Error> {
        let conn = self.pool.get()?;
        diesel::delete(
            schema::reports::dsl::reports.filter(schema::reports::dsl::fog_report_id.eq(report_id)),
        )
        .execute(&conn)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_common::logger::{log, test_with_logger, Logger};
    use mc_crypto_keys::RistrettoPublic;
    use mc_fog_test_infra::db_tests::{random_block, random_kex_rng_pubkey};
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{collections::HashSet, iter::FromIterator};

    #[test_with_logger]
    fn test_new_ingest_invocation(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = test_utils::SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();

        let ingress_key1 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key1, 0).unwrap();

        let egress_key1 = random_kex_rng_pubkey(&mut rng);
        let invoc_id1 = db
            .new_ingest_invocation(None, &ingress_key1, &egress_key1, 0)
            .unwrap();
        log::info!(logger, "first invoc id: {}", invoc_id1);

        let ingress_key2 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key2, 100).unwrap();

        let egress_key2 = random_kex_rng_pubkey(&mut rng);
        let invoc_id2 = db
            .new_ingest_invocation(None, &ingress_key2, &egress_key2, 100)
            .unwrap();
        log::info!(logger, "second invoc id: {}", invoc_id2);

        assert_ne!(invoc_id1, invoc_id2);

        // Both ingest invocations should appear in the ingest_invocations table
        let conn = db_test_context.new_conn();
        let ingest_invocations: Vec<models::IngestInvocation> =
            schema::ingest_invocations::dsl::ingest_invocations
                .order_by(schema::ingest_invocations::dsl::id)
                .load(&conn)
                .expect("failed getting ingest invocations");

        assert_eq!(ingest_invocations.len(), 2);

        assert_eq!(
            IngestInvocationId::from(ingest_invocations[0].id),
            invoc_id1
        );
        assert_eq!(*ingest_invocations[0].ingress_public_key, ingress_key1);
        assert_eq!(
            ingest_invocations[0].egress_public_key,
            egress_key1.public_key
        );
        assert_eq!(
            ingest_invocations[0].rng_version as u32,
            egress_key1.version
        );
        assert_eq!(ingest_invocations[0].start_block, 0);
        assert_eq!(ingest_invocations[0].decommissioned, false);

        assert_eq!(
            IngestInvocationId::from(ingest_invocations[1].id),
            invoc_id2
        );
        assert_eq!(*ingest_invocations[1].ingress_public_key, ingress_key2);
        assert_eq!(
            ingest_invocations[1].egress_public_key,
            egress_key2.public_key
        );
        assert_eq!(
            ingest_invocations[1].rng_version as u32,
            egress_key2.version
        );
        assert_eq!(ingest_invocations[1].start_block, 100);
        assert_eq!(ingest_invocations[1].decommissioned, false);
    }

    #[test_with_logger]
    fn test_get_ingestable_ranges(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = test_utils::SqlRecoveryDbTestContext::new(logger);
        let db = db_test_context.get_db_instance();

        // Should return an empty array when we have no invocations.
        let ranges = db.get_ingestable_ranges().unwrap();
        assert!(ranges.is_empty());

        let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key, 123).unwrap();

        // Add an ingest invocation and see that we can see it.
        let invoc_id1 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 123)
            .unwrap();

        let ranges = db.get_ingestable_ranges().unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].id, invoc_id1);
        assert_eq!(ranges[0].start_block, 123);
        assert_eq!(ranges[0].decommissioned, false);
        assert_eq!(ranges[0].last_ingested_block, None);

        // Add an ingested block and see that last_ingested_block gets updated.
        for block_index in 123..130 {
            let (block, records) = random_block(&mut rng, block_index, 10);

            db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();

            let ranges = db.get_ingestable_ranges().unwrap();
            assert_eq!(ranges.len(), 1);
            assert_eq!(ranges[0].id, invoc_id1);
            assert_eq!(ranges[0].start_block, 123);
            assert_eq!(ranges[0].decommissioned, false);
            assert_eq!(ranges[0].last_ingested_block, Some(block_index));
        }

        // Add another ingest invocation and see we get the expected data.
        let invoc_id2 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 1020)
            .unwrap();

        let ranges = db.get_ingestable_ranges().unwrap();
        assert_eq!(ranges.len(), 2);

        assert_eq!(ranges[0].id, invoc_id1);
        assert_eq!(ranges[0].start_block, 123);
        assert_eq!(ranges[0].decommissioned, false);
        assert_eq!(ranges[0].last_ingested_block, Some(129));

        assert_eq!(ranges[1].id, invoc_id2);
        assert_eq!(ranges[1].start_block, 1020);
        assert_eq!(ranges[1].decommissioned, false);
        assert_eq!(ranges[1].last_ingested_block, None);

        // Decomission the first ingest invocation and validate the returned data.
        db.decommission_ingest_invocation(&invoc_id1).unwrap();

        let ranges = db.get_ingestable_ranges().unwrap();
        assert_eq!(ranges.len(), 2);

        assert_eq!(ranges[0].id, invoc_id1);
        assert_eq!(ranges[0].start_block, 123);
        assert_eq!(ranges[0].decommissioned, true);
        assert_eq!(ranges[0].last_ingested_block, Some(129));

        assert_eq!(ranges[1].id, invoc_id2);
        assert_eq!(ranges[1].start_block, 1020);
        assert_eq!(ranges[1].decommissioned, false);
        assert_eq!(ranges[1].last_ingested_block, None);

        // Decomission the second ingest invocation and validate the returned data.
        db.decommission_ingest_invocation(&invoc_id2).unwrap();

        let ranges = db.get_ingestable_ranges().unwrap();
        assert_eq!(ranges.len(), 2);

        assert_eq!(ranges[0].id, invoc_id1);
        assert_eq!(ranges[0].start_block, 123);
        assert_eq!(ranges[0].decommissioned, true);
        assert_eq!(ranges[0].last_ingested_block, Some(129));

        assert_eq!(ranges[1].id, invoc_id2);
        assert_eq!(ranges[1].start_block, 1020);
        assert_eq!(ranges[1].decommissioned, true);
        assert_eq!(ranges[1].last_ingested_block, None);
    }

    #[test_with_logger]
    fn test_decommission_ingest_invocation(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = test_utils::SqlRecoveryDbTestContext::new(logger);
        let db = db_test_context.get_db_instance();

        let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key, 123).unwrap();

        let invoc_id1 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 123)
            .unwrap();

        let invoc_id2 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 456)
            .unwrap();

        // Initially both ingest invocations should not be decommissioned.
        let ranges = db.get_ingestable_ranges().unwrap();
        assert_eq!(ranges.len(), 2);

        assert_eq!(ranges[0].id, invoc_id1);
        assert_eq!(ranges[0].start_block, 123);
        assert_eq!(ranges[0].decommissioned, false);
        assert_eq!(ranges[0].last_ingested_block, None);

        assert_eq!(ranges[1].id, invoc_id2);
        assert_eq!(ranges[1].start_block, 456);
        assert_eq!(ranges[1].decommissioned, false);
        assert_eq!(ranges[1].last_ingested_block, None);

        // Ensure we do not have any decommissioning events.
        let (events, next_start_from_user_event_id) = db.search_user_events(0).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(
                    |event| if let FogUserEvent::DecommissionIngestInvocation(_) = event {
                        true
                    } else {
                        false
                    }
                )
                .count(),
            0
        );

        // Decommission the 2nd ingest invocation and test again
        db.decommission_ingest_invocation(&invoc_id2).unwrap();

        let ranges = db.get_ingestable_ranges().unwrap();
        assert_eq!(ranges.len(), 2);

        assert_eq!(ranges[0].id, invoc_id1);
        assert_eq!(ranges[0].start_block, 123);
        assert_eq!(ranges[0].decommissioned, false);
        assert_eq!(ranges[0].last_ingested_block, None);

        assert_eq!(ranges[1].id, invoc_id2);
        assert_eq!(ranges[1].start_block, 456);
        assert_eq!(ranges[1].decommissioned, true);
        assert_eq!(ranges[1].last_ingested_block, None);

        // We should have one decommissioning event.
        let (events, next_start_from_user_event_id) = db
            .search_user_events(next_start_from_user_event_id)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            FogUserEvent::DecommissionIngestInvocation(
                mc_fog_types::view::DecommissionedIngestInvocation {
                    ingest_invocation_id: *ranges[1].id,
                    last_ingested_block: 0,
                },
            ),
        );

        // Decommission an invalid ingest invocation id
        let result = db.decommission_ingest_invocation(&IngestInvocationId::from(123));
        assert!(result.is_err());

        // Decommission the 1st ingest invocation by creating a third invocation.
        let invoc_id3_kex_rng_pubkey = random_kex_rng_pubkey(&mut rng);
        let invoc_id3 = db
            .new_ingest_invocation(
                Some(invoc_id1),
                &ingress_key,
                &invoc_id3_kex_rng_pubkey,
                456,
            )
            .unwrap();

        let ranges = db.get_ingestable_ranges().unwrap();
        assert_eq!(ranges.len(), 3);

        assert_eq!(ranges[0].id, invoc_id1);
        assert_eq!(ranges[0].start_block, 123);
        assert_eq!(ranges[0].decommissioned, true);
        assert_eq!(ranges[0].last_ingested_block, None);

        assert_eq!(ranges[1].id, invoc_id2);
        assert_eq!(ranges[1].start_block, 456);
        assert_eq!(ranges[1].decommissioned, true);
        assert_eq!(ranges[1].last_ingested_block, None);

        assert_eq!(ranges[2].id, invoc_id3);
        assert_eq!(ranges[2].start_block, 456);
        assert_eq!(ranges[2].decommissioned, false);
        assert_eq!(ranges[2].last_ingested_block, None);

        // We should have one decommissioning event and one new ingest invocation event.
        let (events, _next_start_from_user_event_id) = db
            .search_user_events(next_start_from_user_event_id)
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            FogUserEvent::DecommissionIngestInvocation(
                mc_fog_types::view::DecommissionedIngestInvocation {
                    ingest_invocation_id: *ranges[0].id,
                    last_ingested_block: 0,
                },
            ),
        );
        assert_eq!(
            events[1],
            FogUserEvent::NewRngRecord(mc_fog_types::view::RngRecord {
                ingest_invocation_id: *invoc_id3,
                pubkey: invoc_id3_kex_rng_pubkey,
                start_block: 456,
            })
        );
    }

    #[test_with_logger]
    fn test_add_block_data(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = test_utils::SqlRecoveryDbTestContext::new(logger);
        let db = db_test_context.get_db_instance();
        let conn = db_test_context.new_conn();

        let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key, 20).unwrap();

        let invoc_id1 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 10)
            .unwrap();

        let invoc_id2 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 15)
            .unwrap();

        let (block1, mut records1) = random_block(&mut rng, 20, 10);
        records1.sort_by_key(|rec| rec.search_key.clone()); // this makes comparing tests result predictable.

        let (block2, mut records2) = random_block(&mut rng, 21, 15);
        records2.sort_by_key(|rec| rec.search_key.clone()); // this makes comparing tests result predictable.

        // Get the last_active_at of the two ingest invocations so we could compare to
        // it later.
        let invocs_last_active_at: Vec<chrono::NaiveDateTime> =
            schema::ingest_invocations::dsl::ingest_invocations
                .select(schema::ingest_invocations::dsl::last_active_at)
                .order_by(schema::ingest_invocations::dsl::id)
                .load(&conn)
                .unwrap();
        let mut invoc1_orig_last_active_at = invocs_last_active_at[0].clone();
        let invoc2_orig_last_active_at = invocs_last_active_at[1].clone();

        // Sleep a second so that the timestamp update would show if it happens.
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Add the block data to the first invocation and test that everything got
        // written correctly.
        db.add_block_data(&invoc_id1, &block1, 0, &records1)
            .unwrap();

        let blocks: Vec<models::IngestedBlock> = schema::ingested_blocks::dsl::ingested_blocks
            .order_by(schema::ingested_blocks::dsl::id)
            .load(&conn)
            .unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            IngestInvocationId::from(blocks[0].ingest_invocation_id),
            invoc_id1
        );
        assert_eq!(blocks[0].block_number as u64, block1.index);
        assert_eq!(
            blocks[0].cumulative_txo_count as u64,
            block1.cumulative_txo_count
        );

        let e_tx_out_records = db
            .get_tx_outs_by_block_and_key(ingress_key, block1.index)
            .unwrap()
            .unwrap();
        assert_eq!(e_tx_out_records.len(), 10);
        assert_eq!(e_tx_out_records.len(), records1.len());
        for (expected_record, written_record) in records1.iter().zip(e_tx_out_records.iter()) {
            assert_eq!(written_record.search_key, expected_record.search_key);
            assert_eq!(written_record.payload, expected_record.payload);
        }

        // Last active at of invoc1 should've updated
        let invocs_last_active_at: Vec<chrono::NaiveDateTime> =
            schema::ingest_invocations::dsl::ingest_invocations
                .select(schema::ingest_invocations::dsl::last_active_at)
                .order_by(schema::ingest_invocations::dsl::id)
                .load(&conn)
                .unwrap();
        assert!(invocs_last_active_at[0] > invoc1_orig_last_active_at);
        assert_eq!(invocs_last_active_at[1], invoc2_orig_last_active_at);

        invoc1_orig_last_active_at = invocs_last_active_at[0].clone();

        // Sleep so that timestamp change is noticeable if it happens
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Adding the same block again should fail.
        assert_eq!(
            db.add_block_data(&invoc_id1, &block1, 0, &records1)
                .unwrap(),
            AddBlockDataStatus {
                block_already_scanned_with_this_key: true
            }
        );
        assert_eq!(
            db.add_block_data(&invoc_id1, &block1, 0, &records2)
                .unwrap(),
            AddBlockDataStatus {
                block_already_scanned_with_this_key: true
            }
        );

        // Timestamps should not change.
        let invocs_last_active_at: Vec<chrono::NaiveDateTime> =
            schema::ingest_invocations::dsl::ingest_invocations
                .select(schema::ingest_invocations::dsl::last_active_at)
                .order_by(schema::ingest_invocations::dsl::id)
                .load(&conn)
                .unwrap();
        assert_eq!(invocs_last_active_at[0], invoc1_orig_last_active_at);
        assert_eq!(invocs_last_active_at[1], invoc2_orig_last_active_at);

        // Add a different block to the 2nd ingest invocation.
        db.add_block_data(&invoc_id2, &block2, 0, &records2)
            .unwrap();
        assert_eq!(
            db.add_block_data(&invoc_id2, &block2, 0, &records1)
                .unwrap(),
            AddBlockDataStatus {
                block_already_scanned_with_this_key: true
            }
        );

        let blocks: Vec<models::IngestedBlock> = schema::ingested_blocks::dsl::ingested_blocks
            .order_by(schema::ingested_blocks::dsl::id)
            .load(&conn)
            .unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(
            IngestInvocationId::from(blocks[0].ingest_invocation_id),
            invoc_id1
        );
        assert_eq!(blocks[0].block_number as u64, block1.index);
        assert_eq!(
            blocks[0].cumulative_txo_count as u64,
            block1.cumulative_txo_count
        );

        assert_eq!(
            IngestInvocationId::from(blocks[1].ingest_invocation_id),
            invoc_id2
        );
        assert_eq!(blocks[1].block_number as u64, block2.index);
        assert_eq!(
            blocks[1].cumulative_txo_count as u64,
            block2.cumulative_txo_count
        );

        let mut e_tx_out_records = db
            .get_tx_outs_by_block_and_key(ingress_key, block1.index)
            .unwrap()
            .unwrap();
        let mut e_tx_out_records_b1 = db
            .get_tx_outs_by_block_and_key(ingress_key, block2.index)
            .unwrap()
            .unwrap();
        e_tx_out_records.append(&mut e_tx_out_records_b1);
        assert_eq!(e_tx_out_records.len(), 25);
        assert_eq!(e_tx_out_records.len(), records1.len() + records2.len());

        // Last active at of invoc2 should've updated
        let invocs_last_active_at: Vec<chrono::NaiveDateTime> =
            schema::ingest_invocations::dsl::ingest_invocations
                .select(schema::ingest_invocations::dsl::last_active_at)
                .order_by(schema::ingest_invocations::dsl::id)
                .load(&conn)
                .unwrap();
        assert_eq!(invocs_last_active_at[0], invoc1_orig_last_active_at);
        assert!(invocs_last_active_at[1] > invoc2_orig_last_active_at);
    }

    #[test_with_logger]
    fn test_search_user_events(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = test_utils::SqlRecoveryDbTestContext::new(logger);
        let db = db_test_context.get_db_instance();

        let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key, 123).unwrap();

        // Create 3 new ingest invocations.
        let kex_rng_pubkeys: Vec<KexRngPubkey> =
            (0..3).map(|_| random_kex_rng_pubkey(&mut rng)).collect();

        let invoc_ids: Vec<_> = kex_rng_pubkeys
            .iter()
            .map(|kex_rng_pubkey| {
                db.new_ingest_invocation(None, &ingress_key, kex_rng_pubkey, 123)
                    .unwrap()
            })
            .collect();

        // Add a decomission record
        db.decommission_ingest_invocation(&invoc_ids[1]).unwrap();

        // Add two missing block records.
        let ingress_key1 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key1, 10).unwrap();
        db.set_report(
            &ingress_key1,
            "",
            &ReportData {
                pubkey_expiry: 20,
                ingest_invocation_id: None,
                report: Default::default(),
            },
        )
        .unwrap();
        db.report_lost_ingress_key(ingress_key1).unwrap();

        let ingress_key2 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key2, 30).unwrap();
        db.set_report(
            &ingress_key2,
            "",
            &ReportData {
                pubkey_expiry: 40,
                ingest_invocation_id: None,
                report: Default::default(),
            },
        )
        .unwrap();
        db.report_lost_ingress_key(ingress_key2).unwrap();

        // Search for events and verify the results.
        let (events, _) = db.search_user_events(0).unwrap();
        assert_eq!(
            events,
            vec![
                FogUserEvent::NewRngRecord(mc_fog_types::view::RngRecord {
                    ingest_invocation_id: *invoc_ids[0],
                    pubkey: kex_rng_pubkeys[0].clone(),
                    start_block: 123,
                }),
                FogUserEvent::NewRngRecord(mc_fog_types::view::RngRecord {
                    ingest_invocation_id: *invoc_ids[1],
                    pubkey: kex_rng_pubkeys[1].clone(),
                    start_block: 123,
                }),
                FogUserEvent::NewRngRecord(mc_fog_types::view::RngRecord {
                    ingest_invocation_id: *invoc_ids[2],
                    pubkey: kex_rng_pubkeys[2].clone(),
                    start_block: 123,
                }),
                FogUserEvent::DecommissionIngestInvocation(
                    mc_fog_types::view::DecommissionedIngestInvocation {
                        ingest_invocation_id: *invoc_ids[1],
                        last_ingested_block: 0
                    }
                ),
                FogUserEvent::MissingBlocks(mc_fog_types::common::BlockRange {
                    start_block: 10,
                    end_block: 20
                }),
                FogUserEvent::MissingBlocks(mc_fog_types::common::BlockRange {
                    start_block: 30,
                    end_block: 40
                })
            ]
        );

        // Searching with a start_from_user_id that is higher than the highest available
        // one should return nothing.
        let (_events, next_start_from_user_event_id) = db.search_user_events(0).unwrap();

        let (events, next_start_from_user_event_id2) = db
            .search_user_events(next_start_from_user_event_id)
            .unwrap();
        assert_eq!(events.len(), 0);
        assert_eq!(
            next_start_from_user_event_id,
            next_start_from_user_event_id2
        );

        let (events, next_start_from_user_event_id2) = db
            .search_user_events(next_start_from_user_event_id + 1)
            .unwrap();
        assert_eq!(events.len(), 0);
        assert_eq!(
            next_start_from_user_event_id + 1,
            next_start_from_user_event_id2,
            "Expected to recieve next_start_from_user_event_id equal to query when no new values are found: {} != {}", next_start_from_user_event_id + 1, next_start_from_user_event_id2,
        );
    }

    #[test_with_logger]
    fn test_get_tx_outs(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = test_utils::SqlRecoveryDbTestContext::new(logger);
        let db = db_test_context.get_db_instance();

        let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key, 123).unwrap();

        let invoc_id = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 123)
            .unwrap();

        let first_block_index = 10;

        let (block1, records1) = random_block(&mut rng, first_block_index, 10);
        db.add_block_data(&invoc_id, &block1, 0, &records1).unwrap();

        let (block2, records2) = random_block(&mut rng, first_block_index + 1, 10);
        db.add_block_data(&invoc_id, &block2, 0, &records2).unwrap();

        // Search for non-existent keys, all should be NotFound
        for test_case in &[
            vec![],
            vec![vec![]],
            vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]],
            vec![[1; 32].to_vec()],
        ] {
            let results = db.get_tx_outs(0, test_case).unwrap();
            assert_eq!(
                results,
                test_case
                    .iter()
                    .map(|search_key| TxOutSearchResult {
                        search_key: search_key.clone(),
                        result_code: TxOutSearchResultCode::NotFound as u32,
                        ciphertext: vec![]
                    })
                    .collect::<Vec<_>>()
            );
        }

        // Search for some non-existent keys and some that we expect to find.
        let test_case = vec![
            vec![1, 2, 3, 4],
            records1[0].search_key.clone(),
            records1[5].search_key.clone(),
            records2[3].search_key.clone(),
            vec![5, 6, 7, 8],
        ];
        let results = db.get_tx_outs(0, &test_case).unwrap();
        assert_eq!(
            results,
            vec![
                TxOutSearchResult {
                    search_key: test_case[0].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
                TxOutSearchResult {
                    search_key: test_case[1].clone(),
                    result_code: TxOutSearchResultCode::Found as u32,
                    ciphertext: records1[0].payload.clone(),
                },
                TxOutSearchResult {
                    search_key: test_case[2].clone(),
                    result_code: TxOutSearchResultCode::Found as u32,
                    ciphertext: records1[5].payload.clone(),
                },
                TxOutSearchResult {
                    search_key: test_case[3].clone(),
                    result_code: TxOutSearchResultCode::Found as u32,
                    ciphertext: records2[3].payload.clone(),
                },
                TxOutSearchResult {
                    search_key: test_case[4].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
            ]
        );

        let results = db.get_tx_outs(first_block_index, &test_case).unwrap();
        assert_eq!(
            results,
            vec![
                TxOutSearchResult {
                    search_key: test_case[0].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
                TxOutSearchResult {
                    search_key: test_case[1].clone(),
                    result_code: TxOutSearchResultCode::Found as u32,
                    ciphertext: records1[0].payload.clone(),
                },
                TxOutSearchResult {
                    search_key: test_case[2].clone(),
                    result_code: TxOutSearchResultCode::Found as u32,
                    ciphertext: records1[5].payload.clone(),
                },
                TxOutSearchResult {
                    search_key: test_case[3].clone(),
                    result_code: TxOutSearchResultCode::Found as u32,
                    ciphertext: records2[3].payload.clone(),
                },
                TxOutSearchResult {
                    search_key: test_case[4].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
            ]
        );

        // Searching with a start_block that filters out the results should filter them
        // as expected.
        let results = db.get_tx_outs(first_block_index + 5, &test_case).unwrap();
        assert_eq!(
            results,
            vec![
                TxOutSearchResult {
                    search_key: test_case[0].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
                TxOutSearchResult {
                    search_key: test_case[1].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
                TxOutSearchResult {
                    search_key: test_case[2].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
                TxOutSearchResult {
                    search_key: test_case[3].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
                TxOutSearchResult {
                    search_key: test_case[4].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
            ]
        );

        let results = db.get_tx_outs(first_block_index + 1, &test_case).unwrap();
        assert_eq!(
            results,
            vec![
                TxOutSearchResult {
                    search_key: test_case[0].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
                TxOutSearchResult {
                    search_key: test_case[1].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
                TxOutSearchResult {
                    search_key: test_case[2].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
                TxOutSearchResult {
                    search_key: test_case[3].clone(),
                    result_code: TxOutSearchResultCode::Found as u32,
                    ciphertext: records2[3].payload.clone(),
                },
                TxOutSearchResult {
                    search_key: test_case[4].clone(),
                    result_code: TxOutSearchResultCode::NotFound as u32,
                    ciphertext: vec![]
                },
            ]
        );
    }

    #[test_with_logger]
    fn test_get_tx_outs_by_block_and_key(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = test_utils::SqlRecoveryDbTestContext::new(logger);
        let db = db_test_context.get_db_instance();

        let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key, 122).unwrap();

        let invoc_id1 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 122)
            .unwrap();

        let invoc_id2 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 123)
            .unwrap();

        let (block1, records1) = random_block(&mut rng, 122, 10);
        db.add_block_data(&invoc_id1, &block1, 0, &records1)
            .unwrap();

        let (block2, records2) = random_block(&mut rng, 123, 10);
        db.add_block_data(&invoc_id2, &block2, 0, &records2)
            .unwrap();

        // Get tx outs for a key we're not aware of or a block id we're not aware of
        // should return None
        let tx_outs = db.get_tx_outs_by_block_and_key(ingress_key, 124).unwrap();
        assert_eq!(tx_outs, None);

        let tx_outs = db
            .get_tx_outs_by_block_and_key(CompressedRistrettoPublic::from_random(&mut rng), 123)
            .unwrap();
        assert_eq!(tx_outs, None);

        // Getting tx outs for ingress key and block number that were previously written
        // should work as expected.
        let tx_outs = db
            .get_tx_outs_by_block_and_key(ingress_key, block1.index)
            .unwrap()
            .unwrap();
        assert_eq!(tx_outs, records1);

        let tx_outs = db
            .get_tx_outs_by_block_and_key(ingress_key, block2.index)
            .unwrap()
            .unwrap();
        assert_eq!(tx_outs, records2);
    }

    #[test_with_logger]
    fn test_get_highest_block_index(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = test_utils::SqlRecoveryDbTestContext::new(logger);
        let db = db_test_context.get_db_instance();

        let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key, 120).unwrap();

        let invoc_id1 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 120)
            .unwrap();

        let invoc_id2 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 120)
            .unwrap();

        assert_eq!(db.get_highest_known_block_index().unwrap(), None);

        let (block, records) = random_block(&mut rng, 123, 10);
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();

        assert_eq!(db.get_highest_known_block_index().unwrap(), Some(123));

        let (block, records) = random_block(&mut rng, 122, 10);
        db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();

        assert_eq!(db.get_highest_known_block_index().unwrap(), Some(123));

        let (block, records) = random_block(&mut rng, 125, 10);
        db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();

        assert_eq!(db.get_highest_known_block_index().unwrap(), Some(125));

        let (block, records) = random_block(&mut rng, 120, 10);
        db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();

        assert_eq!(db.get_highest_known_block_index().unwrap(), Some(125));
    }

    fn create_report(name: &str) -> VerificationReport {
        let chain = pem::parse_many(mc_crypto_x509_test_vectors::ok_rsa_chain_25519_leaf().0)
            .into_iter()
            .map(|p| p.contents)
            .collect();

        VerificationReport {
            sig: format!("{} sig", name).into_bytes().into(),
            chain,
            http_body: format!("{} body", name),
        }
    }

    #[test_with_logger]
    fn test_reports_db(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = test_utils::SqlRecoveryDbTestContext::new(logger);
        let db = db_test_context.get_db_instance();

        let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
        db.new_ingress_key(&ingress_key, 123).unwrap();

        let invoc_id1 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 123)
            .unwrap();

        let invoc_id2 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 123)
            .unwrap();

        // We start with no reports.
        assert_eq!(db.get_all_reports().unwrap(), vec![]);

        // Insert a report and see that we can get it back.
        let report_id1 = "";
        let report1 = ReportData {
            ingest_invocation_id: Some(invoc_id1),
            report: create_report(report_id1),
            pubkey_expiry: 102030,
        };
        let key_status = db.set_report(&ingress_key, report_id1, &report1).unwrap();
        assert_eq!(key_status.pubkey_expiry, 102030);

        assert_eq!(
            db.get_all_reports().unwrap(),
            vec![(report_id1.into(), report1.clone())]
        );

        // Insert another report and see that we can get it back.
        let report_id2 = "report 2";
        let report2 = ReportData {
            ingest_invocation_id: Some(invoc_id2),
            report: create_report(report_id2),
            pubkey_expiry: 10203040,
        };
        let key_status = db.set_report(&ingress_key, report_id2, &report2).unwrap();
        assert_eq!(key_status.pubkey_expiry, 10203040);

        assert_eq!(
            db.get_all_reports().unwrap(),
            vec![
                (report_id1.into(), report1),
                (report_id2.into(), report2.clone()),
            ]
        );

        // Update an existing report.
        let updated_report1 = ReportData {
            ingest_invocation_id: Some(invoc_id2),
            report: create_report("updated_report1"),
            pubkey_expiry: 424242,
        };

        db.set_report(&ingress_key, report_id1, &updated_report1)
            .unwrap();
        assert_eq!(
            key_status.pubkey_expiry, 10203040,
            "pubkey expiry should not have decreased"
        );

        assert_eq!(
            db.get_all_reports().unwrap(),
            vec![
                (report_id1.into(), updated_report1),
                (report_id2.into(), report2.clone()),
            ]
        );

        // Delete the first report and ensure it got removed.
        db.remove_report(report_id1).unwrap();

        assert_eq!(
            db.get_all_reports().unwrap(),
            vec![(report_id2.into(), report2.clone())]
        );

        // Retire the ingress public key
        db.retire_ingress_key(&ingress_key, true).unwrap();

        let report1 = ReportData {
            ingest_invocation_id: Some(invoc_id1),
            report: create_report(report_id1),
            pubkey_expiry: 10203050,
        };
        let key_status = db.set_report(&ingress_key, report_id1, &report1).unwrap();
        assert_eq!(
            key_status.pubkey_expiry, 10203040,
            "pubkey expiry should not have increased after retiring the key"
        );

        // Unretire the ingress public key
        db.retire_ingress_key(&ingress_key, false).unwrap();

        let report1 = ReportData {
            ingest_invocation_id: Some(invoc_id1),
            report: create_report(report_id1),
            pubkey_expiry: 10203060,
        };
        let key_status = db.set_report(&ingress_key, report_id1, &report1).unwrap();
        assert_eq!(
            key_status.pubkey_expiry, 10203060,
            "pubkey expiry should have increased again after unretiring the key"
        );
    }

    #[test_with_logger]
    fn test_get_ingress_key_records(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = test_utils::SqlRecoveryDbTestContext::new(logger);
        let db = db_test_context.get_db_instance();

        // At first, there are no records.
        assert_eq!(db.get_ingress_key_records(0).unwrap(), vec![],);

        // Add an ingress key and see that we can retreive it.
        let ingress_key1 = CompressedRistrettoPublic::from_random(&mut rng);
        db.new_ingress_key(&ingress_key1, 123).unwrap();

        assert_eq!(
            db.get_ingress_key_records(0).unwrap(),
            vec![IngressPublicKeyRecord {
                key: ingress_key1.clone(),
                status: IngressPublicKeyStatus {
                    start_block: 123,
                    pubkey_expiry: 0,
                    retired: false,
                    lost: false,
                },
                last_scanned_block: None,
            }],
        );

        // Add another ingress key and check that we can find it as well.
        let ingress_key2 = CompressedRistrettoPublic::from_random(&mut rng);
        db.new_ingress_key(&ingress_key2, 456).unwrap();

        assert_eq!(
            HashSet::<IngressPublicKeyRecord>::from_iter(db.get_ingress_key_records(0).unwrap()),
            HashSet::from_iter(vec![
                IngressPublicKeyRecord {
                    key: ingress_key1.clone(),
                    status: IngressPublicKeyStatus {
                        start_block: 123,
                        pubkey_expiry: 0,
                        retired: false,
                        lost: false,
                    },
                    last_scanned_block: None,
                },
                IngressPublicKeyRecord {
                    key: ingress_key2.clone(),
                    status: IngressPublicKeyStatus {
                        start_block: 456,
                        pubkey_expiry: 0,
                        retired: false,
                        lost: false,
                    },
                    last_scanned_block: None,
                }
            ])
        );

        // Publish a few blocks and check that last_scanned_block gets updated as
        // expected.
        let invoc_id1 = db
            .new_ingest_invocation(None, &ingress_key1, &random_kex_rng_pubkey(&mut rng), 123)
            .unwrap();

        for block_id in 123..=130 {
            let (block, records) = random_block(&mut rng, block_id, 10);
            db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();

            assert_eq!(
                HashSet::<IngressPublicKeyRecord>::from_iter(
                    db.get_ingress_key_records(0).unwrap()
                ),
                HashSet::from_iter(vec![
                    IngressPublicKeyRecord {
                        key: ingress_key1.clone(),
                        status: IngressPublicKeyStatus {
                            start_block: 123,
                            pubkey_expiry: 0,
                            retired: false,
                            lost: false,
                        },
                        last_scanned_block: Some(block_id),
                    },
                    IngressPublicKeyRecord {
                        key: ingress_key2.clone(),
                        status: IngressPublicKeyStatus {
                            start_block: 456,
                            pubkey_expiry: 0,
                            retired: false,
                            lost: false,
                        },
                        last_scanned_block: None,
                    }
                ])
            );
        }

        // Publishing an old block should not afftect last_scanned_block.
        let (block, records) = random_block(&mut rng, 50, 10);
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();

        assert_eq!(
            HashSet::<IngressPublicKeyRecord>::from_iter(db.get_ingress_key_records(0).unwrap()),
            HashSet::from_iter(vec![
                IngressPublicKeyRecord {
                    key: ingress_key1.clone(),
                    status: IngressPublicKeyStatus {
                        start_block: 123,
                        pubkey_expiry: 0,
                        retired: false,
                        lost: false,
                    },
                    last_scanned_block: Some(130),
                },
                IngressPublicKeyRecord {
                    key: ingress_key2.clone(),
                    status: IngressPublicKeyStatus {
                        start_block: 456,
                        pubkey_expiry: 0,
                        retired: false,
                        lost: false,
                    },
                    last_scanned_block: None,
                }
            ])
        );

        // Check that retiring behaves as expected.
        db.retire_ingress_key(&ingress_key1, true).unwrap();

        assert_eq!(
            HashSet::<IngressPublicKeyRecord>::from_iter(db.get_ingress_key_records(0).unwrap()),
            HashSet::from_iter(vec![
                IngressPublicKeyRecord {
                    key: ingress_key1.clone(),
                    status: IngressPublicKeyStatus {
                        start_block: 123,
                        pubkey_expiry: 0,
                        retired: true,
                        lost: false,
                    },
                    last_scanned_block: Some(130),
                },
                IngressPublicKeyRecord {
                    key: ingress_key2.clone(),
                    status: IngressPublicKeyStatus {
                        start_block: 456,
                        pubkey_expiry: 0,
                        retired: false,
                        lost: false,
                    },
                    last_scanned_block: None,
                }
            ])
        );

        // Check that pubkey expiry behaves as expected
        db.set_report(
            &ingress_key2,
            "",
            &ReportData {
                ingest_invocation_id: None,
                report: create_report(""),
                pubkey_expiry: 888,
            },
        )
        .unwrap();

        assert_eq!(
            HashSet::<IngressPublicKeyRecord>::from_iter(db.get_ingress_key_records(0).unwrap()),
            HashSet::from_iter(vec![
                IngressPublicKeyRecord {
                    key: ingress_key1.clone(),
                    status: IngressPublicKeyStatus {
                        start_block: 123,
                        pubkey_expiry: 0,
                        retired: true,
                        lost: false,
                    },
                    last_scanned_block: Some(130),
                },
                IngressPublicKeyRecord {
                    key: ingress_key2.clone(),
                    status: IngressPublicKeyStatus {
                        start_block: 456,
                        pubkey_expiry: 888,
                        retired: false,
                        lost: false,
                    },
                    last_scanned_block: None,
                }
            ])
        );

        // Which invocation id published the block shouldn't matter, last_scanned_block
        // should continue to move forward.
        for block_id in 456..=460 {
            let invoc_id = db
                .new_ingest_invocation(
                    None,
                    &ingress_key2,
                    &random_kex_rng_pubkey(&mut rng),
                    block_id,
                )
                .unwrap();

            let (block, records) = random_block(&mut rng, block_id, 10);
            db.add_block_data(&invoc_id, &block, 0, &records).unwrap();

            assert_eq!(
                HashSet::<IngressPublicKeyRecord>::from_iter(
                    db.get_ingress_key_records(0).unwrap()
                ),
                HashSet::from_iter(vec![
                    IngressPublicKeyRecord {
                        key: ingress_key1.clone(),
                        status: IngressPublicKeyStatus {
                            start_block: 123,
                            pubkey_expiry: 0,
                            retired: true,
                            lost: false,
                        },
                        last_scanned_block: Some(130),
                    },
                    IngressPublicKeyRecord {
                        key: ingress_key2.clone(),
                        status: IngressPublicKeyStatus {
                            start_block: 456,
                            pubkey_expiry: 888,
                            retired: false,
                            lost: false,
                        },
                        last_scanned_block: Some(block_id),
                    }
                ])
            );
        }

        // start_block_at_least filtering works as expected.
        assert_eq!(
            db.get_ingress_key_records(400).unwrap(),
            vec![IngressPublicKeyRecord {
                key: ingress_key2.clone(),
                status: IngressPublicKeyStatus {
                    start_block: 456,
                    pubkey_expiry: 888,
                    retired: false,
                    lost: false,
                },
                last_scanned_block: Some(460),
            }]
        );
    }
}
