// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_util_uri::{Uri, UriScheme};

pub use mc_util_uri::{ConnectionUri, FogUri, UriParseError};

/// Fog View Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct FogViewScheme {}

impl UriScheme for FogViewScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "fog-view";
    const SCHEME_INSECURE: &'static str = "insecure-fog-view";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 443;
    const DEFAULT_INSECURE_PORT: u16 = 3225;
}

/// Fog Ledger Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct FogLedgerScheme {}

impl UriScheme for FogLedgerScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "fog-ledger";
    const SCHEME_INSECURE: &'static str = "insecure-fog-ledger";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 443;
    const DEFAULT_INSECURE_PORT: u16 = 3223;
}

/// Fog Ingest Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct FogIngestScheme {}

impl UriScheme for FogIngestScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "fog-ingest";
    const SCHEME_INSECURE: &'static str = "insecure-fog-ingest";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 443;
    const DEFAULT_INSECURE_PORT: u16 = 3221;
}

/// Ingest Peer Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct IngestPeerScheme {}
impl UriScheme for IngestPeerScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "igp";
    const SCHEME_INSECURE: &'static str = "insecure-igp";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 8453;
    const DEFAULT_INSECURE_PORT: u16 = 8090;
}

/// Uri used when talking to fog-view service, with the right default ports and
/// scheme.
pub type FogViewUri = Uri<FogViewScheme>;
/// Uri used when talking to fog-ledger service, with the right default ports
/// and scheme.
pub type FogLedgerUri = Uri<FogLedgerScheme>;
/// Uri used when talking to fog-ingest service, with the right default ports
/// and scheme.
pub type FogIngestUri = Uri<FogIngestScheme>;
/// Usi used when talking to fog-ingest-peer service.
pub type IngestPeerUri = Uri<IngestPeerScheme>;

#[cfg(test)]
mod tests {
    use super::{FogLedgerUri, FogViewUri};
    use crate::ConnectionUri;
    use core::str::FromStr;
    use mc_common::ResponderId;

    #[test]
    fn test_valid_fog_ledger_uris() {
        let uri = FogLedgerUri::from_str("fog-ledger://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:443");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("127.0.0.1:443").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = FogLedgerUri::from_str("fog-ledger://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:443");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:443").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = FogLedgerUri::from_str("fog-ledger://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = FogLedgerUri::from_str("insecure-fog-ledger://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:3223");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("127.0.0.1:3223").unwrap()
        );
        assert_eq!(uri.use_tls(), false);

        let uri =
            FogLedgerUri::from_str("insecure-fog-ledger://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:3223");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:3223").unwrap()
        );
        assert_eq!(uri.use_tls(), false);

        let uri =
            FogLedgerUri::from_str("insecure-fog-ledger://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
    }

    #[test]
    fn test_invalid_fog_ledger_uris() {
        assert!(FogLedgerUri::from_str("http://127.0.0.1/").is_err());
        assert!(FogLedgerUri::from_str("127.0.0.1").is_err());
        assert!(FogLedgerUri::from_str("127.0.0.1:12345").is_err());
        assert!(FogLedgerUri::from_str("fog-ledger://").is_err());
        assert!(FogLedgerUri::from_str("fog-ledger:///").is_err());
        assert!(FogLedgerUri::from_str("fog-ledger://    /").is_err());
    }

    #[test]
    fn test_fog_ledger_tls_override() {
        assert_eq!(
            FogLedgerUri::from_str("fog-ledger://node.com/")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            FogLedgerUri::from_str("fog-ledger://node.com/?")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            FogLedgerUri::from_str("fog-ledger://node.com/?tls-hostname=")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            FogLedgerUri::from_str("fog-ledger://node.com/?tls-hostname=lol.com")
                .unwrap()
                .tls_hostname_override(),
            Some("lol.com".into())
        );
    }

    #[test]
    fn test_valid_fog_view_uris() {
        let uri = FogViewUri::from_str("fog-view://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:443");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("127.0.0.1:443").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = FogViewUri::from_str("fog-view://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:443");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:443").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = FogViewUri::from_str("fog-view://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = FogViewUri::from_str("insecure-fog-view://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:3225");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("127.0.0.1:3225").unwrap()
        );
        assert_eq!(uri.use_tls(), false);

        let uri = FogViewUri::from_str("insecure-fog-view://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:3225");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:3225").unwrap()
        );
        assert_eq!(uri.use_tls(), false);

        let uri =
            FogViewUri::from_str("insecure-fog-view://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
    }

    #[test]
    fn test_invalid_fog_view_uris() {
        assert!(FogViewUri::from_str("http://127.0.0.1/").is_err());
        assert!(FogViewUri::from_str("127.0.0.1").is_err());
        assert!(FogViewUri::from_str("127.0.0.1:12345").is_err());
        assert!(FogViewUri::from_str("fog-view://").is_err());
        assert!(FogViewUri::from_str("fog-view:///").is_err());
        assert!(FogViewUri::from_str("fog-view://    /").is_err());
    }

    #[test]
    fn test_fog_view_tls_override() {
        assert_eq!(
            FogViewUri::from_str("fog-view://node.com/")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            FogViewUri::from_str("fog-view://node.com/?")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            FogViewUri::from_str("fog-view://node.com/?tls-hostname=")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            FogViewUri::from_str("fog-view://node.com/?tls-hostname=lol.com")
                .unwrap()
                .tls_hostname_override(),
            Some("lol.com".into())
        );
    }
}
