use bip39::{Language, Mnemonic, MnemonicType};
use mc_account_keys::AccountKey;
use mc_account_keys_slip10::Slip10Key;

fn main() {
    let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
    println!("PHRASE: {}", mnemonic.phrase());
    println!(
        "{}",
        AccountKey::from(Slip10Key::from(mnemonic)).default_subaddress()
    );
}
