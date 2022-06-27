/*
use mc_api::external::KnownTokenId;
use mc_transaction_core::{tokens, Token};
use std::collections::HashMap;

// Test that protobuf KnownTokens enum matches the tokens in mc-transaction-core
#[test]
fn test_known_tokens_enum_vs_mc_transaction_core_tokens() {
    // Collect known tokens from proto
    let mut known_tokens = HashMap::<String, i32>::default();

    let descriptor = KnownTokenId::enum_descriptor_static();
    for value in KnownTokenId::values() {
        known_tokens.insert(
            descriptor.value_by_number(value.value()).name().to_string(),
            value.value(),
        );
    }

    assert_eq!(known_tokens.len(), 1);
    assert_eq!(*known_tokens.get("MOB").unwrap() as u64, *tokens::Mob::ID);
}
    */
