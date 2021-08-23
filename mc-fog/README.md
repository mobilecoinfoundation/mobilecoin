mc-fog
======

This directory contains all the aspects of fog api, fog signature, and fog
report validation that are needed to compile a desktop wallet like mobilecoind
that does not use the fog services itself, but can send to a fog-enabled account.

The fog servers, their APIs, and anything needed for a fog-enabled client (which
uses fog services to perform balance checks etc.) are in the fog directory.
