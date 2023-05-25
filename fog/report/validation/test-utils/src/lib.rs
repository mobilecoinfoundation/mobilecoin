pub use mc_account_keys::PublicAddress;
pub use mc_fog_report_validation::{FogPubkeyError, FogPubkeyResolver, FullyValidatedFogPubkey};
use std::collections::BTreeMap;

/// A mock fog resolver for tests, which skips all IAS, x509, and grpc
/// It maps Fog-urls (Strings) to FullyValidatedFogPubkey
///
/// DO NOT use this except in test code!
#[derive(Default, Debug, Clone)]
pub struct MockFogResolver(pub BTreeMap<String, FullyValidatedFogPubkey>);

impl FogPubkeyResolver for MockFogResolver {
    fn get_fog_pubkey(
        &self,
        addr: &PublicAddress,
    ) -> Result<FullyValidatedFogPubkey, FogPubkeyError> {
        if let Some(fog_url) = addr.fog_report_url() {
            if let Some(result) = self.0.get(fog_url) {
                Ok(result.clone())
            } else {
                Err(FogPubkeyError::NoMatchingReportResponse(
                    fog_url.to_string(),
                ))
            }
        } else {
            Err(FogPubkeyError::NoFogReportUrl)
        }
    }
}
