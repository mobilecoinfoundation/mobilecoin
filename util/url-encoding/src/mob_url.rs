//! Representation of a mob-scheme url, based on rust-url lib
//!
//! This does not follow the pattern of mc-util-uri because this url is not
//! actually used as the basis of a connection to a service, it's rather an
//! encoding that represents a public address, or a payment request following
//! the url specification. It is intended to be more or less human readable
//! and could be used e.g. in an email where a user might actually look at the
//! url, and could be registered with the OS so that a mobilecoin client launches
//! to handle the url.
//!
//! Because we don't implement ConnectionUri, don't really have a notion of port,
//! and aren't required to actually have a hostname (fog-less mob url's don't),
//! we don't really want to base this on the mc-util-uri type.

pub use mc_util_uri::UriParseError;

use crate::error::Error;
use core::{
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};
use mc_crypto_keys::RistrettoPublic;
use mc_transaction_core::account_keys::PublicAddress;
use mc_util_uri::{ConnectionUri, FogScheme, FogUri, UriScheme};
use url::Url;

pub const MOB_SCHEME_SECURE: &str = "mob";
pub const MOB_SCHEME_INSECURE: &str = "insecure-mob";

const SIG_KEY: &str = "s";
const AMOUNT_KEY: &str = "a";
const MEMO_KEY: &str = "m";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MobUrl {
    /// The original Url object used to construct this object.
    url: Url,
    /// Whether to use TLS when connecting.
    use_tls: bool,
}

impl MobUrl {
    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn use_tls(&self) -> bool {
        self.use_tls
    }

    // query parameters
    fn get_param(&self, name: &str) -> Option<String> {
        self.url().query_pairs().find_map(|(k, v)| {
            if k == name && !v.is_empty() {
                Some(v.to_string())
            } else {
                None
            }
        })
    }

    // TODO: We should test what happens when there are duplicated keys among the query pairs
    fn set_param(&mut self, name: &str, val: &str) {
        self.url.query_pairs_mut().append_pair(name, val);
    }

    pub fn get_amount(&self) -> Option<String> {
        self.get_param(AMOUNT_KEY)
    }

    pub fn get_report_id(&self) -> Option<String> {
        self.url.fragment().map(|s| s.to_string())
    }

    pub fn get_memo(&self) -> Option<String> {
        self.get_param(MEMO_KEY)
    }

    pub fn get_sig(&self) -> Option<String> {
        self.get_param(SIG_KEY)
    }

    pub fn set_amount(&mut self, amt: u64) {
        self.set_param(AMOUNT_KEY, &amt.to_string());
    }

    pub fn set_report_id(&mut self, id: Option<&str>) {
        self.url.set_fragment(id);
    }

    pub fn set_memo(&mut self, memo: &str) {
        self.set_param(MEMO_KEY, memo);
    }

    pub fn set_sig(&mut self, sig: &str) {
        self.set_param(SIG_KEY, sig);
    }
}

impl AsRef<str> for MobUrl {
    fn as_ref(&self) -> &str {
        self.url.as_ref()
    }
}

impl Display for MobUrl {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.as_ref())
    }
}

impl FromStr for MobUrl {
    type Err = UriParseError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(src).map_err(|err| UriParseError::UrlParse(src.to_string(), err))?;

        let use_tls = if url.scheme().starts_with(MOB_SCHEME_SECURE) {
            true
        } else if url.scheme().starts_with(MOB_SCHEME_INSECURE) {
            false
        } else {
            return Err(UriParseError::UnknownScheme(
                &MOB_SCHEME_SECURE,
                &MOB_SCHEME_INSECURE,
            ));
        };

        Ok(Self { url, use_tls })
    }
}

// How to construct a MobUrl from a public address
impl TryFrom<&PublicAddress> for MobUrl {
    type Error = Error;
    fn try_from(src: &PublicAddress) -> Result<MobUrl, Error> {
        // Start by trying to parse the fog url from the string, and extract raw url type
        let (fog_url, use_tls) = if let Some(fog_url) = src.fog_report_url() {
            let fog_url = FogUri::from_str(fog_url).map_err(Error::FogUrl)?;
            (fog_url.url().clone(), fog_url.use_tls())
        } else {
            (
                Url::from_str("fog://").expect("Url parsing failed unexpectedly"),
                true,
            )
        };

        // Convert to raw Url type (note: we don't clone because fog_url is not used further)
        let mut mob_url = fog_url;

        // Take care of scheme
        mob_url
            .set_scheme(if use_tls {
                MOB_SCHEME_SECURE
            } else {
                MOB_SCHEME_INSECURE
            })
            .expect("mob scheme was rejected");

        // Compute path part (the encoding of A and B)
        let path = {
            let mut buffer = [0u8; 64];
            (&mut buffer[0..32]).clone_from_slice(&src.spend_public_key().to_bytes()[..]);
            (&mut buffer[32..64]).clone_from_slice(&src.view_public_key().to_bytes()[..]);
            "/".to_owned() + &base64::encode_config(&buffer[..], base64::URL_SAFE)
        };
        mob_url.set_path(&path);

        // Query pairs
        {
            let mut query_pairs = mob_url.query_pairs_mut();

            if let Some(sig) = src.fog_authority_sig() {
                let encoded_sig = base64::encode_config(sig, base64::URL_SAFE);
                query_pairs.append_pair(SIG_KEY, &encoded_sig);
            }
        }

        if let Some(id) = src.fog_report_id() {
            mob_url.set_fragment(Some(id));
        }

        let mob_url_str: &str = mob_url.as_ref();
        MobUrl::from_str(mob_url_str).map_err(Error::MobUrl)
    }
}

// How to extract a public address from a MobUrl
impl TryFrom<&MobUrl> for PublicAddress {
    type Error = Error;
    fn try_from(src: &MobUrl) -> Result<PublicAddress, Error> {
        let mut path = src.url().path();
        while path.starts_with('/') {
            path = &path[1..];
        }

        let decoded_path = base64::decode_config(path, base64::URL_SAFE).map_err(Error::Path)?;
        if decoded_path.len() != 64 {
            return Err(Error::UnexpectedUrlPathLength(decoded_path.len()));
        }
        let spend_public = RistrettoPublic::try_from(&decoded_path[0..32])?;
        let view_public = RistrettoPublic::try_from(&decoded_path[32..64])?;

        // Mob Url's that have host, have fog
        Ok(if let Some(_host) = src.url().host_str() {
            let fog_url = {
                let mut fog_url = src.url().clone();
                fog_url
                    .set_scheme(if src.use_tls() {
                        FogScheme::SCHEME_SECURE
                    } else {
                        FogScheme::SCHEME_INSECURE
                    })
                    .expect("fog scheme was rejected");
                fog_url.set_path("");
                // TODO: Perhaps we should preserve query parameters that are not "known" keys? Such as tls-override etc.
                fog_url.set_query(None);
                fog_url.set_fragment(None);
                let fog_url = fog_url.into_string();

                // For extra validation, check that it parses as a fog url
                FogUri::from_str(&fog_url).map_err(Error::FogUrl)?;

                fog_url
            };

            // May have report_key
            let report_id = src.get_report_id().unwrap_or_default();

            // Probably the mob-url also has fog_authority_sig
            let sig_vec = if let Some(sig_str) = src.get_sig() {
                base64::decode_config(&sig_str, base64::URL_SAFE).map_err(Error::FogAuthoritySig)?
            } else {
                b"".to_vec()
            };

            PublicAddress::new_with_fog(&spend_public, &view_public, fog_url, report_id, sig_vec)
        } else {
            // TODO: Could return an error if e.g. fog_authority_sig is present but host is missing?
            PublicAddress::new(&spend_public, &view_public)
        })
    }
}
