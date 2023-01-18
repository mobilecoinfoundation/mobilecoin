// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "user_event_type"))]
    pub struct UserEventType;
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    ingest_invocations (id) {
        id -> Int8,
        ingress_public_key -> Bytea,
        egress_public_key -> Bytea,
        last_active_at -> Timestamp,
        start_block -> Int8,
        decommissioned -> Bool,
        rng_version -> Int4,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    ingested_blocks (id) {
        id -> Int8,
        ingest_invocation_id -> Int8,
        ingress_public_key -> Bytea,
        block_number -> Int8,
        cumulative_txo_count -> Int8,
        block_signature_timestamp -> Int8,
        proto_ingested_block_data -> Bytea,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    ingress_keys (ingress_public_key) {
        ingress_public_key -> Bytea,
        start_block -> Int8,
        pubkey_expiry -> Int8,
        retired -> Bool,
        lost -> Bool,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    reports (id) {
        id -> Int8,
        ingress_public_key -> Bytea,
        ingest_invocation_id -> Nullable<Int8>,
        fog_report_id -> Varchar,
        report -> Bytea,
        pubkey_expiry -> Int8,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;
    use super::sql_types::UserEventType;

    user_events (id) {
        id -> Int8,
        event_type -> UserEventType,
        new_ingest_invocation_id -> Nullable<Int8>,
        decommission_ingest_invocation_id -> Nullable<Int8>,
        missing_blocks_start -> Nullable<Int8>,
        missing_blocks_end -> Nullable<Int8>,
    }
}

diesel::joinable!(ingested_blocks -> ingest_invocations (ingest_invocation_id));
diesel::joinable!(reports -> ingest_invocations (ingest_invocation_id));
diesel::joinable!(reports -> ingress_keys (ingress_public_key));

diesel::allow_tables_to_appear_in_same_query!(
    ingest_invocations,
    ingested_blocks,
    ingress_keys,
    reports,
    user_events,
);
