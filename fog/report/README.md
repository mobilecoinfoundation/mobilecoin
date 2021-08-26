report
======

The fog report server serves reports from the fog ingest server which are published
to the world at large. All mobilecoin clients that support sending fog users
must be able to talk to the fog report server, and validate the fog report,
and extract the key from it.

The crates mc-fog-report-api, mc-fog-report-validation, and mc-fog-report-types are all used for
this, and are dependencies of all mobilecoin wallets including e.g. mobilecoind
and desktop wallets that do not use the fog services themselves.

The fog-report-server serves its data from postgres.
The fog-report-cli is a diagnostic tool that can hitting fog-report and parse
and validate the report.
