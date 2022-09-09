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

mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn invalid_keys() {
        let result = get_address("a", "b");
        assert_eq!(
            result,
            Err(JsValue::from(
                "Failed to parse view_private_key: Odd number of digits"
            ))
        );
    }

    #[wasm_bindgen_test]
    fn valid_keys() {
        let result = get_address(
            "5ea069957773a6415fdba501642579c6121a2c9cc2300989f98872ef70af9e13",
            "00c992f14f3c7862267eca290d2cff8212b2335e3e00a5f17ff0ba9e24f7874f",
        );
        assert_eq!(
            result,
            Ok("4VucmHjybn9EhXo5eoTy7RcgBPw7bWgeBta3tQnnvSoKsCnWXtt6berF97hBsKJYeMgzMXy4DFHJ25mnGoDVvQHAKDTt2siDdPoChyejWkW".to_string())
        );
    }
}
