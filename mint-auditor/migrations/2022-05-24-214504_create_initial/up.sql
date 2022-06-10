-- Audit data per block
CREATE TABLE block_audit_data (
    -- Diesel requires having a primary key and sqlite doesn't allow 64 bit primay keys, so even though
    -- we would've wanted to use the block_index for that we can't.
    -- Must be nullable for auto-increment: https://www.sqlite.org/autoinc.html
    id INT PRIMARY KEY,
    block_index UNSIGNED BIGINT NOT NULL
    -- Future revision would add gnosis safe data here
);
CREATE UNIQUE INDEX idx__block_audit_data__block_index ON block_audit_data(block_index);

-- Balance per token, for each block we have audited.
CREATE TABLE block_balance (
    -- Diesel requires having a primary key and sqlite doesn't allow 64 bit primay keys, so even though
    -- we would've wanted to use the block_index for that we can't.
    -- Must be nullable for auto-increment: https://www.sqlite.org/autoinc.html
    id INT PRIMARY KEY,
    block_index UNSIGNED BIGINT NOT NULL,
    token_id UNSIGNED BIGINT NOT NULL,
    balance UNSIGNED BIGINT NOT NULL,
    -- Constaints
    FOREIGN KEY (block_index) REFERENCES block_audit_data(block_index),
    UNIQUE(block_index, token_id)
);

-- Mint configs txs
CREATE TABLE mint_config_txs (
    -- Must be nullable for auto-increment: https://www.sqlite.org/autoinc.html
    id INT PRIMARY KEY,
    -- The block index at which this mint config tx appreared.
    block_index UNSIGNED BIGINT NOT NULL,
    -- The token id this mint config tx is for.
    token_id UNSIGNED BIGINT NOT NULL,
    -- The nonce, as hex-encoded bytes.
    nonce VARCHAR NOT NULL UNIQUE,
    -- The maximal amount that can be minted by configurations specified in
    -- this tx. This amount is shared amongst all configs.
    mint_limit UNSIGNED BIGINT NOT NULL,
    -- Tombstone block.
    tombstone_block UNSIGNED BIGINT NOT NULL,
    -- The protobuf-serialized MintConfigTx.
    protobuf BLOB NOT NULL,
    -- Constraints
    UNIQUE (block_index, token_id)
);

-- Mint configs
CREATE TABLE mint_configs (
    -- Diesel requires having a primary key and sqlite doesn't allow 64 bit primay keys.
    -- Must be nullable for auto-increment: https://www.sqlite.org/autoinc.html
    id INT PRIMARY KEY,
    -- The mint config tx id this config is for.
    mint_config_tx_id INT NOT NULL,
    -- The maximal amount this configuration can mint from the moment it has
    -- been applied.
    mint_limit UNSIGNED BIGINT NOT NULL,
    -- The protobuf-serialized MintConfig.
    protobuf BLOB NOT NULL,
    -- Constraints
    FOREIGN KEY (mint_config_tx_id) REFERENCES mint_config_txs(id)
);

-- Mint txs
CREATE TABLE mint_txs (
    -- Diesel requires having a primary key and sqlite doesn't allow 64 bit primay keys.
    -- Must be nullable for auto-increment: https://www.sqlite.org/autoinc.html
    id INT PRIMARY KEY,
    -- The token id this mint tx is for.
    token_id UNSIGNED BIGINT NOT NULL,
    -- The amount that was minted.
    amount UNSIGNED BIGINT NOT NULL,
    -- The nonce, as hex-encoded bytes.
    nonce VARCHAR NOT NULL UNIQUE,
    -- The recipient of the mint.
    recipient_b58_address VARCHAR NOT NULL,
    -- Tombstone block.
    tombstone_block UNSIGNED BIGINT NOT NULL,
    -- The protobuf-serialized MintTx.
    protobuf BLOB NOT NULL,
    -- The mint config, when we are able to match it with one.
    mint_config_id INT,
    -- Constraints
    FOREIGN KEY (mint_config_id) REFERENCES mint_configs(id)
);

-- Counters - this table is expected to only ever have a single row.
CREATE TABLE counters (
    -- Diesel only supports tables with primary keys, so we need one.
    -- Not nullable because we only have a single row in this table and the code that inserts to it hard-codes the id to 0.
    id INTEGER NOT NULL PRIMARY KEY,

    -- Number of blocks we've synced so far.
    num_blocks_synced UNSIGNED BIGINT NOT NULL,

    -- Number of times we've encountered a burn that exceeds the calculated balance.
    num_burns_exceeding_balance UNSIGNED BIGINT NOT NULL,

    -- Number of `MintTx`s that did not match an active mint config.
    num_mint_txs_without_matching_mint_config UNSIGNED BIGINT NOT NULL
);

