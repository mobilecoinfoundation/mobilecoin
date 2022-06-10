table! {
    block_audit_data (id) {
        id -> Nullable<Integer>,
        block_index -> BigInt,
    }
}

table! {
    block_balance (id) {
        id -> Nullable<Integer>,
        block_index -> BigInt,
        token_id -> BigInt,
        balance -> BigInt,
    }
}

table! {
    counters (id) {
        id -> Integer,
        num_blocks_synced -> BigInt,
        num_burns_exceeding_balance -> BigInt,
        num_mint_txs_without_matching_mint_config -> BigInt,
    }
}

table! {
    mint_config_txs (id) {
        id -> Nullable<Integer>,
        block_index -> BigInt,
        token_id -> BigInt,
        nonce -> Text,
        mint_limit -> BigInt,
        tombstone_block -> BigInt,
        protobuf -> Binary,
    }
}

table! {
    mint_configs (id) {
        id -> Nullable<Integer>,
        mint_config_tx_id -> Integer,
        mint_limit -> BigInt,
        protobuf -> Binary,
    }
}

table! {
    mint_txs (id) {
        id -> Nullable<Integer>,
        token_id -> BigInt,
        amount -> BigInt,
        nonce -> Text,
        recipient_b58_address -> Text,
        tombstone_block -> BigInt,
        protobuf -> Binary,
        mint_config_id -> Nullable<Integer>,
    }
}

joinable!(mint_configs -> mint_config_txs (mint_config_tx_id));
joinable!(mint_txs -> mint_configs (mint_config_id));

allow_tables_to_appear_in_same_query!(
    block_audit_data,
    block_balance,
    counters,
    mint_config_txs,
    mint_configs,
    mint_txs,
);
