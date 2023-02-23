attest-verifier-config
======================

This crate specifies and implements a method for configuring an attestation
verifier based on sigstructs and other configuration data, which it finds using
a search path which is given to it. This search path is called the "attestation
trust root search path".

This is loosely based on how OS'es like linux often have a designated path where SSL trust roots are stored,
e.g. `/etc/ssl/certs`, `/usr/local/share/certs`. This is a bit different in that,
we're not assuming that there's an OS level path for mobilecoin attestation roots,
rather it's expected that when a mobilecoin client installs itself, somewhere in its installation
path it would install this trust root file. The app would then load that data using the code in this crate.
So, these trust roots would be private to an installation of the app.

Format
------

We propose that the verifier config is stored in a file called e.g. `trusted-measurements.json`.

The file has the following (example) schema:

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
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657]
       },
       "fog-ingest": {
           "MRENCLAVE": "a8af815564569aae3558d8e4e4be14d1bcec896623166a10494b4eaea3e1c48c",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657]
       },
       "fog-ledger": {
           "MRENCLAVE": "da209f4b24e8f4471bd6440c4e9f1b3100f1da09e2836d236e285b274901ed3b",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657]
       },
       "fog-view": {
           "MRENCLAVE": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657]
       }
    }
}
```

Here, the outermost layer is a list of enclave versions that are trusted. Usually, clients should trust
the current release and the next release. These measurements can be checked against the mobilecoin github
releases page: https://github.com/mobilecoinfoundation/mobilecoin/releases.

The use of `MRSIGNER` is also supported, but the product svn (security version number) must be supplied.

```json
...
  "v3": {
    "fog-ingest": {
        "MRSIGNER": "2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e",
        "product_svn": 5,
        "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"],
    }
  }
}
```
