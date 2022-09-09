use mc_account_keys::PublicAddress;
use mc_crypto_keys::RistrettoPublic;
use std::convert::TryFrom;
use wasm_bindgen::{prelude::*, JsValue};

#[wasm_bindgen]
pub fn get_address(view_public_key: &str, spend_public_key: &str) -> Result<String, JsValue> {
    let hex_view = hex::decode(view_public_key)
        .map_err(|err| format!("Failed to parse view_private_key: {}", err))?;

    let v: &[u8] = &hex_view;

    let view_public = RistrettoPublic::try_from(v)
        .map_err(|err| format!("Failed to parse spend_public_key: {:?}", err))?;

    let hex_spend = hex::decode(spend_public_key)
        .map_err(|err| format!("Failed to parse spend_public_key: {}", err))?;

    let s: &[u8] = &hex_spend;

    let spend_public = RistrettoPublic::try_from(s)
        .map_err(|err| format!("Failed to parse spend_public_key: {:?}", err))?;

    let public_address = PublicAddress::new(&spend_public, &view_public);

    let mut wrapper = mc_api::printable::PrintableWrapper::new();
    wrapper.set_public_address((&public_address).into());

    let address = wrapper
        .b58_encode()
        .map_err(|err| format!("Failed to encode address: {}", err))?;

    Ok(address)
}
