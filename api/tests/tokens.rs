use mc_api::external::KnownTokenId;
use mc_transaction_core::{tokens, Token};

// Test that protobuf KnownTokens enum matches the tokens in mc-transaction-core
#[test]
fn test_known_tokens_enum_vs_mc_transaction_core_tokens() {
    let known_tokens = [KnownTokenId::Mob];
    for token in known_tokens.iter() {
        match token {
            KnownTokenId::Mob => {
                assert_eq!(*token as u64, *tokens::Mob::ID);
            }
        }
    }
}
