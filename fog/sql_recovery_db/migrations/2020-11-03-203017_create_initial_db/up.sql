-- Copyright (c) 2018-2021 The MobileCoin Foundation

-- Ingress keys
CREATE TABLE ingress_keys (
    -- The public key bytes
    ingress_public_key BYTEA PRIMARY KEY,
    -- The first block this key could have been used for (or, a lower bound on that, since this is a racy question)
    start_block BIGINT NOT NULL,
    -- The largest pubkey_expiry value that we have ever published in a report for this key.
    -- Can be initialized to 0, if this is less or equal to start_block, it means this key has not actually been published.
    pubkey_expiry BIGINT NOT NULL DEFAULT 0,
    -- Whether this key is retired. When it is retired,
    -- new reports for it are not published anymore.
    -- Servers keep scanning blocks for it up to the largest published pubkey expiry value,
    -- then enter the idle state.
    --
    -- Keys are marked retired when the operator decides to shut down a cluster.
    retired BOOLEAN NOT NULL DEFAULT false,
    -- Whether this key is lost.
    -- When it is lost, all servers that had the private key are gone and we can never scan
    -- any new blocks with it.
    -- This means that the range from last-scanned-block-index to pubkey-expiry is a "missed block range",
    -- if there are any blocks like that.
    -- This is the only way that missed block ranges can occur.
    -- Note: If everything is scanned up to pubkey-expiry then there are no missed blocks, even if lost is true.
    lost BOOLEAN NOT NULL DEFAULT false
);

-- Ingest invocations
CREATE TABLE ingest_invocations (
    id BIGSERIAL PRIMARY KEY,
    -- The ingress public key this ingest invocation is scanning with
    ingress_public_key BYTEA NOT NULL,
    CONSTRAINT ingest_invocations__fk_ingress_keys FOREIGN KEY (ingress_public_key) REFERENCES ingress_keys(ingress_public_key),
    -- The egress key this ingest evocation is generating search keys with
    egress_public_key BYTEA NOT NULL UNIQUE,
    -- The last time this invocation was active
    last_active_at TIMESTAMP NOT NULL,
    -- The first block that this invocation scanned
    start_block BIGINT NOT NULL,
    -- Whether this invocation is decommissioned, which means it won't scan anything again
    decommissioned BOOLEAN NOT NULL DEFAULT false,
    -- The rng algorithm version number
    rng_version INT NOT NULL
);

-- Ingested blocks
CREATE TABLE ingested_blocks (
    id BIGSERIAL PRIMARY KEY,
    -- The invocation id that produced this block record
    ingest_invocation_id BIGINT NOT NULL,
    CONSTRAINT ingested_blocks__fk_ingest_invocation FOREIGN KEY (ingest_invocation_id) REFERENCES ingest_invocations(id),
    -- The ingress public key this ingest invocation is scanning with
    ingress_public_key BYTEA NOT NULL,
    CONSTRAINT ingest_invocations__fk_ingress_keys FOREIGN KEY (ingress_public_key) REFERENCES ingress_keys(ingress_public_key),
    -- The block index in the blockchain
    block_number BIGINT NOT NULL,
    -- The cumulative txo count from the block header
    cumulative_txo_count BIGINT NOT NULL,
    -- The block signature timestamp for this block.
    -- This is a number in seconds since the unix epoch
    block_signature_timestamp BIGINT NOT NULL,
    -- Protobuf encoding additional data, including,
    -- * sequence of ETxOutRecords
    -- See fog-sql-recovery-db crate for schema
    proto_ingested_block_data BYTEA NOT NULL,
    -- A given ingest invocation doesn't scan a block more than once
    UNIQUE (ingest_invocation_id, block_number),
    -- We don't need to scan any block with the same key more than once
    -- If an ingest server tries to write and hits this constraint, it learns it is
    -- is behind someone else in its cluster, and can back off.
    UNIQUE (ingress_public_key, block_number)
);

CREATE INDEX idx_ingested_blocks__block_number ON ingested_blocks (block_number);

-- User events
CREATE TYPE user_event_type AS ENUM ('new_ingest_invocation', 'decommission_ingest_invocation', 'missing_blocks');

CREATE TABLE user_events (
    id BIGSERIAL PRIMARY KEY,
    event_type user_event_type NOT NULL,

    -- For new ingest invocation events:
    new_ingest_invocation_id BIGINT NULL UNIQUE, -- cannot announce twice
    CONSTRAINT user_events__fk_new_ingest_invocation FOREIGN KEY (new_ingest_invocation_id) REFERENCES ingest_invocations(id),

    -- For decommission ingest invocation events:
    decommission_ingest_invocation_id BIGINT NULL UNIQUE, -- cannot decommission twice
    CONSTRAINT user_events__fk_decommissioned_ingest_invocation FOREIGN KEY (decommission_ingest_invocation_id) REFERENCES ingest_invocations(id),

    -- For missing blocks events:
    missing_blocks_start BIGINT NULL, -- first block in the range
    missing_blocks_end BIGINT NULL,   -- one block past the end of the range
    UNIQUE(missing_blocks_start, missing_blocks_end)
);

CREATE INDEX idx_user_events__event_type__id ON user_events (event_type, id);

-- Reports
CREATE TABLE reports (
    id BIGSERIAL PRIMARY KEY,

    -- The ingress key associated to this report
    ingress_public_key BYTEA NOT NULL,
    CONSTRAINT reports__fk_ingress_key FOREIGN KEY (ingress_public_key) REFERENCES ingress_keys(ingress_public_key),

    -- The ingest invocation that generated this report
    -- Note: In some cases, we publish a report before we have an ingest invocation id, which is why NULL is allowed
    ingest_invocation_id BIGINT,
    CONSTRAINT reports__fk_ingest_invocation FOREIGN KEY (ingest_invocation_id) REFERENCES ingest_invocations(id),

    -- The fog_report_id of users with which this pubkey should be used
    -- This should match fog_report_id in Bob's public_address
    fog_report_id VARCHAR(64) NOT NULL UNIQUE,

    -- The signed intel report from Fog ingest node
    -- This report structure includes the pubkey bytes themselves
    -- At time of writing this is a protobuf serialized VerificationReport from attest crate
    report BYTEA NOT NULL,

    -- The last block at which a well-formed client may use this pubkey.
    -- The tombstone block of a Tx formed using this pubkey should not exceed this.
    -- This number is likely to be e.g. current block height + 50,
    -- and may be updated (larger) if you come back to the server later.
    -- TODO: Can postgres enforce that this number doesn't get smaller?
    pubkey_expiry BIGINT NOT NULL
);


-- Disable auto-vacuuming on tables that are append-only
ALTER TABLE user_events SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
ALTER TABLE ingested_blocks SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
