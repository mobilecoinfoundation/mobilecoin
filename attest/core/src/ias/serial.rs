use crate::{VerificationReport, VerificationSignature};
use alloc::{format, string::String, vec::Vec};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

// Intermediate representation of a VerificationReport with hex-encoded strings
#[derive(Serialize, Deserialize)]
struct EncodedReport {
    pub sig: String,
    pub chain: Vec<String>,
    pub http_body: String,
}

/// Serializer for representing ias report signing certificate chain and
/// report signature bytes as hex strings.
pub fn serialize<S: Serializer>(
    report: &Option<VerificationReport>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let encoded_report = report.as_ref().map(|report| {
        let chain = report.chain.iter().map(hex::encode).collect::<Vec<_>>();
        EncodedReport {
            sig: hex::encode(&report.sig),
            chain,
            http_body: report.http_body.clone(),
        }
    });
    encoded_report.serialize(serializer)
}

/// Helper method for deserializing ias reports with key material serialized
/// as hex strings into VerificationReport objects.
pub fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<VerificationReport>, D::Error> {
    let encoded_report: Option<EncodedReport> = Deserialize::deserialize(deserializer)?;
    match encoded_report {
        None => Ok(None),
        Some(encoded_report) => {
            let sig: VerificationSignature = hex::decode(encoded_report.sig.as_str())
                .map_err(|err| D::Error::custom(format!("{}", err)))?
                .into();
            let chain: Vec<Vec<u8>> = encoded_report
                .chain
                .iter()
                .map(|hex_string| hex::decode(hex_string.as_str()).unwrap_or_default())
                .collect();
            Ok(Some(VerificationReport {
                sig,
                chain,
                http_body: encoded_report.http_body,
            }))
        }
    }
}
