// Copyright (c) 2018-2020 MobileCoin Inc.

//! Schemes and uri objects for fog, fog-view, fog-ledger.

use crate::{
    traits::{ConnectionUri, UriScheme},
    uri::Uri,
    UriParseError,
};

use url::Url;

use std::{convert::TryFrom, str::FromStr};

/// Fog Uri Scheme
/// This is the Uri that appears in public addresses,
/// and is used when interacting with fog report server.
/// It contains additional query parameters including a possible shard id,
/// and a signature formed using the fog user's private keys over the
/// fog root authority public key, used to authenticate reports from fog.
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct FogScheme {}

impl UriScheme for FogScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "fog";
    const SCHEME_INSECURE: &'static str = "insecure-fog";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 443;
    const DEFAULT_INSECURE_PORT: u16 = 3229;
}

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

// Fog URI is the location of the fog service as a whole, fog view and fog ledger uri's
// can be derived from it.
// fog_uri.addr() itself is the location of the fog report server, and get_fog_report_label()
// can be used to find the desired report in the response from fog report server.
pub type FogUri = Uri<FogScheme>;
pub type FogViewUri = Uri<FogViewScheme>;
pub type FogLedgerUri = Uri<FogLedgerScheme>;

// Extra API for FogUri
pub trait FogUriApi {
    /// Get the shard-id, if any, that is part of this Fog Uri.
    fn get_shard_id(&self) -> Option<String>;

    /// Get the user's signature over the fog authority's fingerprint, if any, that is part of this Fog Uri.
    fn get_fog_authority_fingerprint_signature(&self) -> Option<String>;

    /// Get the string label that Alice expects to find in report records from the report server when sending
    /// to Bob's public address which has this fog uri.
    ///
    /// This is created by appending the shard id to the uri, and dropping any extra query parameters.
    fn get_fog_report_label(&self) -> Result<String, UriParseError>;

    /// Helper for implementing conversions from FogUri to other schemes
    /// This appends the shard id to the url, and drops the fog authority fingerprint signature.
    /// But preseves any tls / ca-bundle information etc.
    fn append_shard_id_and_change_scheme<Scheme: UriScheme>(
        &self,
    ) -> Result<Uri<Scheme>, UriParseError>;

    /// Internal helper for implementing get_fog_report_label and append_shard_id_and_change_scheme
    /// This makes a url::Url object that has the query parameters removed, and appends the shard_id,
    /// if present, to the path.
    fn internal_append_shard_id(&self) -> Result<Url, UriParseError>;
}

impl FogUriApi for FogUri {
    fn get_shard_id(&self) -> Option<String> {
        self.get_param("n")
    }
    fn get_fog_authority_fingerprint_signature(&self) -> Option<String> {
        self.get_param("s")
    }

    fn get_fog_report_label(&self) -> Result<String, UriParseError> {
        Ok(self.internal_append_shard_id()?.as_str().to_string())
    }

    fn append_shard_id_and_change_scheme<Scheme: UriScheme>(
        &self,
    ) -> Result<Uri<Scheme>, UriParseError> {
        // Clone the url in order to modify it
        let mut url = self.internal_append_shard_id()?;

        // Ensure that we preserve any other query parameters besides "n" and "s",
        // such as ca-bundle or tls-hostname which might be needed in some test context or something.
        url.query_pairs_mut().extend_pairs(
            self.url()
                .query_pairs()
                .filter(|(key, _)| key != "n" && key != "s"),
        );
        // Remove question mark from end of url if it is unnecessary, because it is annoying
        if url.query_pairs().count() == 0 {
            url.set_query(None);
        }

        // Set the scheme in the url according to our current use_tls value
        url.set_scheme(if self.use_tls() {
            Scheme::SCHEME_SECURE
        } else {
            Scheme::SCHEME_INSECURE
        })
        .expect("Scheme was invalid");

        // Convert using from_str
        Uri::from_str(url.as_str())
    }

    // internal detail
    // produce a uri derived from this uri by apprending the shard-id as a url path element,
    // and remove all query parameters
    fn internal_append_shard_id(&self) -> Result<Url, UriParseError> {
        // Clone the url in order to modify it
        let mut url = self.url().clone();

        // Wipe out the query string if any
        url.set_query(None);

        // Append the shard_id of this url to the path
        if let Some(shard_id) = self.get_shard_id() {
            // See url lib documentation around join for why we should have "/" first,
            // if the url does not end in `/` then the shard-id will replace the last path element.
            url = url.join("/").map_err(UriParseError::UrlParse)?;
            url = url.join(&shard_id).map_err(UriParseError::UrlParse)?;
        }

        Ok(url)
    }
}

// Conversions from FogUri to FogViewUri and FogLedgeruri

impl TryFrom<&FogUri> for FogViewUri {
    type Error = UriParseError;
    fn try_from(src: &FogUri) -> Result<Self, Self::Error> {
        src.append_shard_id_and_change_scheme::<FogViewScheme>()
    }
}

impl TryFrom<&FogUri> for FogLedgerUri {
    type Error = UriParseError;
    fn try_from(src: &FogUri) -> Result<Self, Self::Error> {
        src.append_shard_id_and_change_scheme::<FogLedgerScheme>()
    }
}

#[cfg(test)]
mod fog_uri_tests {
    use super::{FogLedgerUri, FogUri, FogUriApi, FogViewUri};
    use core::{convert::TryFrom, str::FromStr};

    // Test FogUri API for some uris without shard id or fingerprint
    #[test]
    fn fog_uri_no_shard_id_no_sig() {
        let uri = FogUri::from_str("fog://fog.signal.com").unwrap();
        assert_eq!(uri.get_shard_id(), None);
        assert_eq!(uri.get_fog_authority_fingerprint_signature(), None);
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://fog.signal.com");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com"
        );

        let uri = FogUri::from_str("fog://fog.signal.com/").unwrap();
        assert_eq!(uri.get_shard_id(), None);
        assert_eq!(uri.get_fog_authority_fingerprint_signature(), None);
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://fog.signal.com/");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com/"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com/"
        );

        assert!(FogUri::from_str("fog.signal.com").is_err());

        let uri = FogUri::from_str("fog://fog.signal.com?tls-hostname=lol.com").unwrap();
        assert_eq!(uri.get_shard_id(), None);
        assert_eq!(uri.get_fog_authority_fingerprint_signature(), None);
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://fog.signal.com");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com?tls-hostname=lol.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com?tls-hostname=lol.com"
        );

        let uri = FogUri::from_str("fog://127.0.0.1").unwrap();
        assert_eq!(uri.get_shard_id(), None);
        assert_eq!(uri.get_fog_authority_fingerprint_signature(), None);
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://127.0.0.1");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://127.0.0.1"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://127.0.0.1"
        );

        let uri = FogUri::from_str("fog://127.0.0.1?tls-hostname=lol.com").unwrap();
        assert_eq!(uri.get_shard_id(), None);
        assert_eq!(uri.get_fog_authority_fingerprint_signature(), None);
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://127.0.0.1");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://127.0.0.1?tls-hostname=lol.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://127.0.0.1?tls-hostname=lol.com"
        );
    }

    // Test FogUri API with shard-id and not with fingerprint
    #[test]
    fn fog_uri_shard_id_no_sig() {
        let uri = FogUri::from_str("fog://fog.signal.com?n=74").unwrap();
        assert_eq!(uri.get_shard_id(), Some("74".to_string()));
        assert_eq!(uri.get_fog_authority_fingerprint_signature(), None);
        assert_eq!(
            uri.get_fog_report_label().unwrap(),
            "fog://fog.signal.com/74"
        );
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com/74"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com/74"
        );

        let uri = FogUri::from_str("fog://fog.signal.com/?n=74").unwrap();
        assert_eq!(uri.get_shard_id(), Some("74".to_string()));
        assert_eq!(uri.get_fog_authority_fingerprint_signature(), None);
        assert_eq!(
            uri.get_fog_report_label().unwrap(),
            "fog://fog.signal.com/74"
        );
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com/74"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com/74"
        );

        assert!(FogUri::from_str("fog.signal.com?n=74").is_err());

        let uri = FogUri::from_str("fog://fog.signal.com?n=74&tls-hostname=lol.com").unwrap();
        assert_eq!(uri.get_shard_id(), Some("74".to_string()));
        assert_eq!(uri.get_fog_authority_fingerprint_signature(), None);
        assert_eq!(
            uri.get_fog_report_label().unwrap(),
            "fog://fog.signal.com/74"
        );
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com/74?tls-hostname=lol.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com/74?tls-hostname=lol.com"
        );

        let uri = FogUri::from_str("fog://127.0.0.1?n=74").unwrap();
        assert_eq!(uri.get_shard_id(), Some("74".to_string()));
        assert_eq!(uri.get_fog_authority_fingerprint_signature(), None);
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://127.0.0.1/74");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://127.0.0.1/74"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://127.0.0.1/74"
        );

        let uri = FogUri::from_str("fog://127.0.0.1?n=74&tls-hostname=lol.com").unwrap();
        assert_eq!(uri.get_shard_id(), Some("74".to_string()));
        assert_eq!(uri.get_fog_authority_fingerprint_signature(), None);
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://127.0.0.1/74");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://127.0.0.1/74?tls-hostname=lol.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://127.0.0.1/74?tls-hostname=lol.com"
        );
    }

    // Test FogUri with shard-id and with fingerprint
    #[test]
    fn fog_uri_shard_id_and_sig() {
        let uri = FogUri::from_str("fog://fog.signal.com?n=74&s=abcdefg").unwrap();
        assert_eq!(uri.get_shard_id(), Some("74".to_string()));
        assert_eq!(
            uri.get_fog_authority_fingerprint_signature(),
            Some("abcdefg".to_string())
        );
        assert_eq!(
            uri.get_fog_report_label().unwrap(),
            "fog://fog.signal.com/74"
        );
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com/74"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com/74"
        );

        let uri = FogUri::from_str("fog://fog.signal.com/?n=74&s=abcdefg").unwrap();
        assert_eq!(uri.get_shard_id(), Some("74".to_string()));
        assert_eq!(
            uri.get_fog_authority_fingerprint_signature(),
            Some("abcdefg".to_string())
        );
        assert_eq!(
            uri.get_fog_report_label().unwrap(),
            "fog://fog.signal.com/74"
        );
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com/74"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com/74"
        );

        assert!(FogUri::from_str("fog.signal.com?n=74&s=abcdefg").is_err());

        let uri =
            FogUri::from_str("fog://fog.signal.com/?n=74&s=abcdefg&tls-hostname=lol.com").unwrap();
        assert_eq!(uri.get_shard_id(), Some("74".to_string()));
        assert_eq!(
            uri.get_fog_authority_fingerprint_signature(),
            Some("abcdefg".to_string())
        );
        assert_eq!(
            uri.get_fog_report_label().unwrap(),
            "fog://fog.signal.com/74"
        );
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com/74?tls-hostname=lol.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com/74?tls-hostname=lol.com"
        );

        let uri = FogUri::from_str("fog://127.0.0.1?n=74&s=abcdefg").unwrap();
        assert_eq!(uri.get_shard_id(), Some("74".to_string()));
        assert_eq!(
            uri.get_fog_authority_fingerprint_signature(),
            Some("abcdefg".to_string())
        );
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://127.0.0.1/74");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://127.0.0.1/74"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://127.0.0.1/74"
        );

        let uri = FogUri::from_str("fog://127.0.0.1?n=74&s=abcdefg&tls-hostname=lol.com").unwrap();
        assert_eq!(uri.get_shard_id(), Some("74".to_string()));
        assert_eq!(
            uri.get_fog_authority_fingerprint_signature(),
            Some("abcdefg".to_string())
        );
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://127.0.0.1/74");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://127.0.0.1/74?tls-hostname=lol.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://127.0.0.1/74?tls-hostname=lol.com"
        );
    }

    // Test FogUri with no shard-id and with fingerprint
    #[test]
    fn fog_uri_no_shard_id_with_sig() {
        let uri = FogUri::from_str("fog://fog.signal.com?s=abcdefg").unwrap();
        assert_eq!(uri.get_shard_id(), None);
        assert_eq!(
            uri.get_fog_authority_fingerprint_signature(),
            Some("abcdefg".to_string())
        );
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://fog.signal.com");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com"
        );

        let uri = FogUri::from_str("fog://fog.signal.com?s=abcdefg").unwrap();
        assert_eq!(uri.get_shard_id(), None);
        assert_eq!(
            uri.get_fog_authority_fingerprint_signature(),
            Some("abcdefg".to_string())
        );
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://fog.signal.com");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com"
        );

        assert!(FogUri::from_str("fog.signal.com?s=abcdefg").is_err());

        let uri = FogUri::from_str("fog://fog.signal.com?s=abcdefg&tls-hostname=lol.com").unwrap();
        assert_eq!(uri.get_shard_id(), None);
        assert_eq!(
            uri.get_fog_authority_fingerprint_signature(),
            Some("abcdefg".to_string())
        );
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://fog.signal.com");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://fog.signal.com?tls-hostname=lol.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://fog.signal.com?tls-hostname=lol.com"
        );

        let uri = FogUri::from_str("fog://127.0.0.1?s=abcdefg").unwrap();
        assert_eq!(uri.get_shard_id(), None);
        assert_eq!(
            uri.get_fog_authority_fingerprint_signature(),
            Some("abcdefg".to_string())
        );
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://127.0.0.1");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://127.0.0.1"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://127.0.0.1"
        );

        let uri = FogUri::from_str("fog://127.0.0.1?s=abcdefg&tls-hostname=lol.com").unwrap();
        assert_eq!(uri.get_shard_id(), None);
        assert_eq!(
            uri.get_fog_authority_fingerprint_signature(),
            Some("abcdefg".to_string())
        );
        assert_eq!(uri.get_fog_report_label().unwrap(), "fog://127.0.0.1");
        assert_eq!(
            FogViewUri::try_from(&uri).unwrap().as_ref(),
            "fog-view://127.0.0.1?tls-hostname=lol.com"
        );
        assert_eq!(
            FogLedgerUri::try_from(&uri).unwrap().as_ref(),
            "fog-ledger://127.0.0.1?tls-hostname=lol.com"
        );
    }
}

#[cfg(test)]
mod fog_ledger_uri_tests {
    use super::FogLedgerUri as ClientUri;
    use crate::ConnectionUri;
    use core::str::FromStr;
    use mc_common::ResponderId;

    #[test]
    fn test_valid_client_uris() {
        let uri = ClientUri::from_str("fog-ledger://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:443");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("127.0.0.1:443").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = ClientUri::from_str("fog-ledger://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:443");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:443").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = ClientUri::from_str("fog-ledger://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), true);

        let uri = ClientUri::from_str("insecure-fog-ledger://127.0.0.1/").unwrap();
        assert_eq!(uri.addr(), "127.0.0.1:3223");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("127.0.0.1:3223").unwrap()
        );
        assert_eq!(uri.use_tls(), false);

        let uri = ClientUri::from_str("insecure-fog-ledger://node1.test.mobilecoin.com/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:3223");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:3223").unwrap()
        );
        assert_eq!(uri.use_tls(), false);

        let uri =
            ClientUri::from_str("insecure-fog-ledger://node1.test.mobilecoin.com:666/").unwrap();
        assert_eq!(uri.addr(), "node1.test.mobilecoin.com:666");
        assert_eq!(
            uri.responder_id().unwrap(),
            ResponderId::from_str("node1.test.mobilecoin.com:666").unwrap()
        );
        assert_eq!(uri.use_tls(), false);
    }

    #[test]
    fn test_invalid_client_uris() {
        assert!(ClientUri::from_str("http://127.0.0.1/").is_err());
        assert!(ClientUri::from_str("127.0.0.1").is_err());
        assert!(ClientUri::from_str("127.0.0.1:12345").is_err());
        assert!(ClientUri::from_str("fog-ledger://").is_err());
        assert!(ClientUri::from_str("fog-ledger:///").is_err());
        assert!(ClientUri::from_str("fog-ledger://    /").is_err());
    }

    #[test]
    fn test_tls_override() {
        assert_eq!(
            ClientUri::from_str("fog-ledger://node.com/")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            ClientUri::from_str("fog-ledger://node.com/?")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            ClientUri::from_str("fog-ledger://node.com/?tls-hostname=")
                .unwrap()
                .tls_hostname_override(),
            None
        );
        assert_eq!(
            ClientUri::from_str("fog-ledger://node.com/?tls-hostname=lol.com")
                .unwrap()
                .tls_hostname_override(),
            Some("lol.com".into())
        );
    }
}
