// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::schema::*;
use crate::sql_types::{SqlCompressedRistrettoPublic, UserEventType};
use mc_fog_types::common::BlockRange;

#[derive(Debug, Queryable)]
pub struct IngressKey {
    pub ingress_public_key: SqlCompressedRistrettoPublic,
    pub start_block: i64,
    pub pubkey_expiry: i64,
    pub retired: bool,
    pub lost: bool,
}

#[derive(Debug, Insertable)]
#[table_name = "ingress_keys"]
pub struct NewIngressKey {
    pub ingress_public_key: Vec<u8>,
    pub start_block: i64,
    pub pubkey_expiry: i64,
    pub retired: bool,
    pub lost: bool,
}

#[derive(Debug, Queryable)]
pub struct IngestInvocation {
    pub id: i64,
    pub ingress_public_key: SqlCompressedRistrettoPublic,
    pub egress_public_key: Vec<u8>,
    pub last_active_at: chrono::NaiveDateTime,
    pub start_block: i64,
    pub decommissioned: bool,
    pub rng_version: i32,
}

#[derive(Debug, Insertable)]
#[table_name = "ingest_invocations"]
pub struct NewIngestInvocation {
    pub ingress_public_key: Vec<u8>,
    pub egress_public_key: Vec<u8>,
    pub last_active_at: chrono::NaiveDateTime,
    pub start_block: i64,
    pub decommissioned: bool,
    pub rng_version: i32,
}

#[derive(Debug, Queryable)]
pub struct IngestedBlock {
    pub id: i64,
    pub ingest_invocation_id: i64,
    pub ingress_public_key: SqlCompressedRistrettoPublic,
    pub block_number: i64,
    pub cumulative_txo_count: i64,
    pub block_signature_timestamp: i64,
    pub proto_ingested_block_data: Vec<u8>,
}

#[derive(Debug, Insertable)]
#[table_name = "ingested_blocks"]
pub struct NewIngestedBlock {
    pub ingress_public_key: Vec<u8>,
    pub ingest_invocation_id: i64,
    pub block_number: i64,
    pub cumulative_txo_count: i64,
    pub block_signature_timestamp: i64,
    pub proto_ingested_block_data: Vec<u8>,
}

#[derive(Debug, Insertable)]
#[table_name = "user_events"]
pub struct NewUserEvent {
    pub event_type: UserEventType,
    pub new_ingest_invocation_id: Option<i64>,
    pub decommission_ingest_invocation_id: Option<i64>,
    pub missing_blocks_start: Option<i64>,
    pub missing_blocks_end: Option<i64>,
}

impl NewUserEvent {
    pub fn new_ingest_invocation(ingest_invocation_id: i64) -> Self {
        Self {
            event_type: UserEventType::NewIngestInvocation,
            new_ingest_invocation_id: Some(ingest_invocation_id),
            decommission_ingest_invocation_id: None,
            missing_blocks_start: None,
            missing_blocks_end: None,
        }
    }

    pub fn decommission_ingest_invocation(ingest_invocation_id: i64) -> Self {
        Self {
            event_type: UserEventType::DecommissionIngestInvocation,
            new_ingest_invocation_id: None,
            decommission_ingest_invocation_id: Some(ingest_invocation_id),
            missing_blocks_start: None,
            missing_blocks_end: None,
        }
    }

    pub fn missing_blocks(block_range: &BlockRange) -> Self {
        assert!(block_range.is_valid());

        Self {
            event_type: UserEventType::MissingBlocks,
            new_ingest_invocation_id: None,
            decommission_ingest_invocation_id: None,
            missing_blocks_start: Some(block_range.start_block as i64),
            missing_blocks_end: Some(block_range.end_block as i64),
        }
    }
}

#[derive(Debug, Insertable)]
#[table_name = "reports"]
pub struct NewReport<'a> {
    pub ingress_public_key: &'a [u8],
    pub ingest_invocation_id: Option<i64>,
    pub fog_report_id: &'a str,
    pub report: &'a [u8],
    pub pubkey_expiry: i64,
}
