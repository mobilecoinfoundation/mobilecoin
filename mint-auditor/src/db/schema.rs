table! {
    block_audit_data (id) {
        id -> Integer,
        block_index -> BigInt,
    }
}

table! {
    block_balance (id) {
        id -> Integer,
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

allow_tables_to_appear_in_same_query!(block_audit_data, block_balance, counters,);
