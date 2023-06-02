attest-verifier-config
======================

A JSON schema for basic attestation configs.

This crate defines a schema for storing a set of trusted measurements for SGX
enclaves in json. These measurements can be grouped by version, and named.

This crate simply provides a serialization format and organizational schema over
the data that is martialed into a Verifier using the builder format.

This is meant to help clients that connect to several MobileCoin enclaves to configure their verifiers
appropriately. Thus, it has more to do with clients than the actual attestation implementation.

Format
------

Verifier config for a network may be stored in a file called e.g. `trusted-measurements.json`.

The file has the following (example) schema, which can be parsed and interpretted by this crate:

```json
{
    "v3": {
       "consensus": {
           "MRENCLAVE": "207c9705bf640fdb960034595433ee1ff914f9154fbe4bc7fc8a97e912961e5c",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-ingest": {
           "MRENCLAVE": "3370f131b41e5a49ed97c4188f7a976461ac6127f8d222a37929ac46b46d560e",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-ledger": {
           "MRENCLAVE": "fd4c1c82cca13fa007be15a4c90e2b506c093b21c2e7021a055cbb34aa232f3f",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"],
       },
       "fog-view": {
           "MRENCLAVE": "dca7521ce4564cc2e54e1637e533ea9d1901c2adcbab0e7a41055e719fb0ff9d",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"],
       }
    },
    "v4": {
       "consensus": {
           "MRENCLAVE": "e35bc15ee92775029a60a715dca05d310ad40993f56ad43bca7e649ccc9021b5",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       },
       "fog-ingest": {
           "MRENCLAVE": "a8af815564569aae3558d8e4e4be14d1bcec896623166a10494b4eaea3e1c48c",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       },
       "fog-ledger": {
           "MRENCLAVE": "da209f4b24e8f4471bd6440c4e9f1b3100f1da09e2836d236e285b274901ed3b",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       },
       "fog-view": {
           "MRENCLAVE": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       }
    }
}
```

Here, the outermost layer is a list of enclave versions that are trusted. Usually, clients should trust
the current release and the next release. These measurements can be checked against the mobilecoin github
releases page: https://github.com/mobilecoinfoundation/mobilecoin/releases.

The use of `MRSIGNER` is also supported, but the product id and minimum SVN (security version number) must be supplied.

```json
{
  "v3": {
    "fog-ingest": {
        "MRSIGNER": "2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e",
        "product_id": 1,
        "minimum_svn": 5,
        "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"],
    }
  }
}
```

It is also possible to specify `mitigated_config_advisories`.

```json
{
  "v3": {
    "fog-ingest": {
        "MRSIGNER": "2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e",
        "product_id": 1,
        "minimum_svn": 5,
        "mitigated_config_advisories": ["INTEL-SA-XXXXX"],
        "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"],
    }
  }
}
```

Suggestions for use
-------------------

It is suggested that clients such as full-service might take the `trusted-measurements.json` file as a startup parameter,
or have a search location.

For mobile clients, it may be more convenient if they bake this json is as a string literal and update it with each
release. Both approaches are reasonable.
