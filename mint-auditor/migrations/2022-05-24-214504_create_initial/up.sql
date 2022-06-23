-- Note about primary keys: For SQLite to auto-increment a PRIMARY KEY row, the column must be `INTEGER PRIMARY KEY`.
-- Even `INT PRIMARY KEY` won't work. It has to be `INTEGER PRIMARY KEY`. See https://www.sqlite.org/autoinc.html.
-- This has an annoying impact on Diesel - it forces the primary key column to be `i32` even though SQLite uses 64 bit for these columns.
-- Diesel also requires that a table has a primary key column, so each table must have one.
--
-- Note about signed/unsigned: SQLite does not support unsigned types. As such, everything is signed and gets represented
-- as i32/i64 on the rust side. Rust code can still safely cast to unsigned types without losing data, but this does mean
-- that SQLite functions will behave incorrectly - for example calling SUM(amount) should be avoided, since SQLite will be
-- summing signed values. The workaround is to do such operations in Rust, after casting to the unsigned type.

-- Audit data per block
CREATE TABLE block_audit_data (
    id INTEGER PRIMARY KEY,
    block_index BIGINT NOT NULL
    -- Future revision would add gnosis safe data here
);
CREATE UNIQUE INDEX idx__block_audit_data__block_index ON block_audit_data(block_index);

-- Balance per token, for each block we have audited.
CREATE TABLE block_balance (
    id INTEGER PRIMARY KEY,
    block_index BIGINT NOT NULL,
    token_id BIGINT NOT NULL,
    balance BIGINT NOT NULL,
    -- Constaints
    FOREIGN KEY (block_index) REFERENCES block_audit_data(block_index),
    UNIQUE(block_index, token_id)
);

-- Mint configs txs
CREATE TABLE mint_config_txs (
    id INTEGER PRIMARY KEY,
    -- The block index at which this mint config tx appreared.
    block_index BIGINT NOT NULL,
    -- The token id this mint config tx is for.
    token_id BIGINT NOT NULL,
    -- The nonce, as hex-encoded bytes.
    nonce VARCHAR(128) NOT NULL UNIQUE,
    -- The maximal amount that can be minted by configurations specified in
    -- this tx. This amount is shared amongst all configs.
    total_mint_limit BIGINT NOT NULL,
    -- Tombstone block.
    tombstone_block BIGINT NOT NULL,
    -- The protobuf-serialized MintConfigTx.
    protobuf BLOB NOT NULL,
    -- Constraints
    UNIQUE (block_index, token_id)
);

-- Mint configs
CREATE TABLE mint_configs (
    id INTEGER PRIMARY KEY,
    -- The mint config tx id this config is for.
    mint_config_tx_id INT NOT NULL,
    -- The maximal amount this configuration can mint from the moment it has
    -- been applied.
    mint_limit BIGINT NOT NULL,
    -- The protobuf-serialized MintConfig.
    protobuf BLOB NOT NULL,
    -- Constraints
    FOREIGN KEY (mint_config_tx_id) REFERENCES mint_config_txs(id)
);

-- Mint txs
CREATE TABLE mint_txs (
    id INTEGER PRIMARY KEY,
    -- The block index at which this mint tx appreared.
    block_index BIGINT NOT NULL,
     -- The token id this mint tx is for.
    token_id BIGINT NOT NULL,
    -- The amount that was minted.
    amount BIGINT NOT NULL,
    -- The nonce, as hex-encoded bytes.
    nonce VARCHAR(128) NOT NULL UNIQUE,
    -- The recipient of the mint.
    recipient_b58_address TEXT NOT NULL,
    -- Tombstone block.
    tombstone_block BIGINT NOT NULL,
    -- The protobuf-serialized MintTx.
    protobuf BLOB NOT NULL,
    -- The mint config, when we are able to match it with one.
    mint_config_id INT,
    -- Constraints
    FOREIGN KEY (mint_config_id) REFERENCES mint_configs(id)
);

-- Processed gnosis safe transactions
CREATE TABLE gnosis_safe_txs (
    eth_tx_hash VARCHAR(66) NOT NULL UNIQUE PRIMARY KEY,
    raw_tx_json TEXT NOT NULL
);

-- Deposits to the gnosis safe.
CREATE TABLE gnosis_safe_deposits (
    id INTEGER PRIMARY KEY,
    eth_tx_hash VARCHAR(66) NOT NULL UNIQUE,
    eth_block_number BIGINT NOT NULL,
    safe_address VARCHAR(42) NOT NULL,
    token_address VARCHAR(42) NOT NULL,
    amount BIGINT NOT NULL,
    -- Constraints
    FOREIGN KEY (eth_tx_hash) REFERENCES gnosis_safe_txs(eth_tx_hash)
);
CREATE INDEX idx__gnosis_safe_deposits__eth_block_number ON gnosis_safe_deposits(eth_block_number);

-- Withdrawals from the gnosis safe.
CREATE TABLE gnosis_safe_withdrawals (
    id INTEGER PRIMARY KEY,
    eth_tx_hash VARCHAR(66) NOT NULL UNIQUE,
    eth_block_number BIGINT NOT NULL,
    safe_address VARCHAR(42) NOT NULL,
    token_address VARCHAR(42) NOT NULL,
    amount BIGINT NOT NULL,
    mc_tx_out_public_key_hex VARCHAR(64) NOT NULL,
    -- Constraints
    FOREIGN KEY (eth_tx_hash) REFERENCES gnosis_safe_txs(eth_tx_hash)
);
CREATE INDEX idx__gnosis_safe_withdrawals__eth_block_number ON gnosis_safe_withdrawals(eth_block_number);
CREATE INDEX idx__gnosis_safe_withdrawals__mc_tx_out_public_key_hex ON gnosis_safe_withdrawals(mc_tx_out_public_key_hex);

-- Counters - this table is expected to only ever have a single row.
CREATE TABLE counters (
    -- Not nullable because we only have a single row in this table and the code that inserts to it hard-codes the id to 0.
    -- This prevents the auto-increment behavior but we don't need that for this table.
    id INTEGER NOT NULL PRIMARY KEY,

    -- Number of blocks we've synced so far.
    num_blocks_synced BIGINT NOT NULL,

    -- Number of times we've encountered a burn that exceeds the calculated balance.
    num_burns_exceeding_balance BIGINT NOT NULL,

    -- Number of `MintTx`s that did not match an active mint config.
    num_mint_txs_without_matching_mint_config BIGINT NOT NULL
);

