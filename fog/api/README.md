fog_api
======

gRPC APIs for fog server components (ingest, view)

View APIs are generally user-facing, i.e. the SDK is expected to call them to
inquire about a user's coins etc.

Ingest APIs are generally not; they are expected to be called by the node
operator to administer the machine (manage key rotation etc.)
