fog_ingest_server
=============

The `fog_ingest_server` is responsible for polling an LMDB ledger database, processing blocks as it finds them, and storing processed data (user txos) into a PostgreSQL database called "recovery_db". Additionally, it exposes a GRPC service for administrative purposes.