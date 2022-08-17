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
    nonce_hex VARCHAR(128) NOT NULL UNIQUE,
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
    nonce_hex VARCHAR(128) NOT NULL UNIQUE,
    -- The recipient of the mint.
    recipient_b58_addr TEXT NOT NULL,
    -- Tombstone block.
    tombstone_block BIGINT NOT NULL,
    -- The protobuf-serialized MintTx.
    protobuf BLOB NOT NULL,
    -- The mint config, when we are able to match it with one.
    mint_config_id INT,
    -- Constraints
    FOREIGN KEY (mint_config_id) REFERENCES mint_configs(id)
);
CREATE INDEX idx_mint_txs__block_index ON mint_txs(block_index);
CREATE INDEX idx_mint_txs__nonce_hex ON mint_txs(nonce_hex);

-- Burn TxOuts
CREATE TABLE burn_tx_outs (
    id INTEGER PRIMARY KEY,
    -- The block index at which this TxOut appeared.
    block_index BIGINT NOT NULL,
     -- The token id this tx out is for.
    token_id BIGINT NOT NULL,
    -- The amount that was burned.
    amount BIGINT NOT NULL,
    -- The tx out public key
    public_key_hex VARCHAR(64) NOT NULL UNIQUE,
    -- The protobuf-serialized TxOut.
    protobuf BLOB NOT NULL
);
CREATE INDEX idx__burn_tx_outs__block_index ON burn_tx_outs(block_index);
CREATE INDEX idx__burn_tx_outs__public_key_hex ON burn_tx_outs(public_key_hex);

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
    safe_addr VARCHAR(42) NOT NULL,
    token_addr VARCHAR(42) NOT NULL,
    amount BIGINT NOT NULL,
    -- This is the expected nonce of the matching MintTx we want to see on the MobileCoin blockchain.
    -- It is derived from eth_tx_hash, but is stored here to make querying easier and more efficient.
    expected_mc_mint_tx_nonce_hex VARCHAR(128) NOT NULL,
    -- Constraints
    FOREIGN KEY (eth_tx_hash) REFERENCES gnosis_safe_txs(eth_tx_hash)
);
CREATE INDEX idx__gnosis_safe_deposits__eth_block_number ON gnosis_safe_deposits(eth_block_number);
CREATE INDEX idx__gnosis_safe_deposits__expected_mc_mint_tx_nonce_hex ON gnosis_safe_deposits(expected_mc_mint_tx_nonce_hex);

-- Withdrawals from the gnosis safe.
CREATE TABLE gnosis_safe_withdrawals (
    id INTEGER PRIMARY KEY,
    eth_tx_hash VARCHAR(66) NOT NULL UNIQUE,
    eth_block_number BIGINT NOT NULL,
    safe_addr VARCHAR(42) NOT NULL,
    token_addr VARCHAR(42) NOT NULL,
    amount BIGINT NOT NULL,
    mc_tx_out_public_key_hex VARCHAR(64) NOT NULL,
    -- Constraints
    FOREIGN KEY (eth_tx_hash) REFERENCES gnosis_safe_txs(eth_tx_hash)
);
CREATE INDEX idx__gnosis_safe_withdrawals__eth_block_number ON gnosis_safe_withdrawals(eth_block_number);
CREATE INDEX idx__gnosis_safe_withdrawals__mc_tx_out_public_key_hex ON gnosis_safe_withdrawals(mc_tx_out_public_key_hex);

-- Mapping between MintTxs and GnosisSafeDeposits that match each other.
-- This essentially is the audit log that shows which mints/deposits were a match.
-- A match means that the nonce, token information (MC token_id and Ethereum contract address) and the amount all matched.
-- If a mint or deposit are not referenced by this table that means something questionable happened.
CREATE TABLE audited_mints (
    id INTEGER PRIMARY KEY,
    mint_tx_id INTEGER NOT NULL,
    gnosis_safe_deposit_id INTEGER NOT NULL,
    -- Constraints
    FOREIGN KEY (mint_tx_id) REFERENCES mint_txs(id),
    FOREIGN KEY (gnosis_safe_deposit_id) REFERENCES gnosis_safe_deposits(id)
);
CREATE INDEX idx__audited_mints__mint_tx_id ON audited_mints(mint_tx_id);
CREATE INDEX idx__audited_mints__gnosis_safe_deposit_id ON audited_mints(gnosis_safe_deposit_id);

-- Mapping between BurnTxOuts and GnosisSafeWithdrawals that match eachother.
-- This essentially is the audit log that shows which burns/withdrawals were a match.
-- A match means that the TxOut public key matched a Gnosis safe withdrawal, and that the token information
-- (MC token_id and Ethereum contract address) as well as the amount all matched.
-- It is possible for a burn to not be referenced by this table if the burn is not actually associated
-- with a withdrawal. This is possible since anyone can issue burn transactions. However, a Gnosis withdrawal
-- is expected to be matched with a burn.
CREATE TABLE audited_burns (
    id INTEGER PRIMARY KEY,
    burn_tx_out_id INTEGER NOT NULL,
    gnosis_safe_withdrawal_id INTEGER NOT NULL,
    -- Constraints
    FOREIGN KEY (burn_tx_out_id) REFERENCES burn_tx_outs(id),
    FOREIGN KEY (gnosis_safe_withdrawal_id) REFERENCES gnosis_safe_withdrawals(id)
);
CREATE INDEX idx__audited_burns__burn_tx_out_id ON audited_burns(burn_tx_out_id);
CREATE INDEX idx__audited_burns__gnosis_safe_withdrawal_id ON audited_burns(gnosis_safe_withdrawal_id);

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
    num_mint_txs_without_matching_mint_config BIGINT NOT NULL,

    -- Number of mismatched mints and Gnosis deposits.
    num_mismatching_mints_and_deposits BIGINT NOT NULL,

    -- Number of mismatched burns and Gnosis withdrawals.
    num_mismatching_burns_and_withdrawals BIGINT NOT NULL,

    -- Number of times we encountered deposits to an unaudited Ethereum token contract address.
    num_unknown_ethereum_token_deposits BIGINT NOT NULL,

    -- Number of times we encountered withdrawals from an unaudited Ethereum token contract address.
    num_unknown_ethereum_token_withdrawals BIGINT NOT NULL,

    -- Number of times we encountered a mint that is associated with an unaudited safe.
    num_mints_to_unknown_safe BIGINT NOT NULL,

    -- Number of times we encountered a burn that is associated with an unaudited safe.
    num_burns_from_unknown_safe BIGINT NOT NULL,

    -- Number of unexpected errors attempting to match deposits to mints.
    num_unexpected_errors_matching_deposits_to_mints BIGINT NOT NULL,

    -- Number of unexpected errors attempting to match mints to deposits.
    num_unexpected_errors_matching_mints_to_deposits BIGINT NOT NULL,

    -- Number of unexpected errors attempting to match withdrawals to burns.
    num_unexpected_errors_matching_withdrawals_to_burns BIGINT NOT NULL,

    -- Number of unexpected errors attempting to match burns to withdrawals.
    num_unexpected_errors_matching_burns_to_withdrawals BIGINT NOT NULL
);

