// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_account_keys::AccountKey;
use mc_crypto_digestible_test_utils::*;
use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint, tokens::Mob, tx::TxOut, Amount, Block, BlockContents,
    BlockVersion, Token,
};
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{RngCore, RngType as FixedRng, SeedableRng};

fn test_accounts() -> Vec<AccountKey> {
    let mut rng: FixedRng = SeedableRng::from_seed([12u8; 32]);
    (0..5).map(|_i| AccountKey::random(&mut rng)).collect()
}

fn test_origin_tx_outs() -> Vec<TxOut> {
    let mut rng: FixedRng = SeedableRng::from_seed([11u8; 32]);

    let accounts = test_accounts();

    accounts
        .iter()
        .map(|acct| {
            let mut tx_out = TxOut::new(
                Amount {
                    value: rng.next_u32() as u64,
                    token_id: Mob::ID,
                },
                &acct.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                EncryptedFogHint::fake_onetime_hint(&mut rng),
            )
            .expect("Could not create TxOut");
            // Origin TxOuts do not have encrypted memo fields.
            tx_out.e_memo = None;
            // Origin TxOuts do not have masked token id
            tx_out.masked_amount.masked_token_id = Default::default();
            tx_out
        })
        .collect()
}

fn test_blockchain(block_version: BlockVersion) -> Vec<(Block, BlockContents)> {
    let mut rng: FixedRng = SeedableRng::from_seed([10u8; 32]);

    let origin_tx_outs = test_origin_tx_outs();
    let origin = Block::new_origin_block(&origin_tx_outs[..]);
    let accounts = test_accounts();
    let recipient_pub_keys = accounts
        .iter()
        .map(|account| account.default_subaddress())
        .collect::<Vec<_>>();

    mc_transaction_core_test_utils::get_blocks(
        block_version,
        &recipient_pub_keys[..],
        3,
        50,
        50,
        &origin,
        &mut rng,
    )
}

#[test]
fn tx_out_digestible_ast() {
    let tx_out = &test_origin_tx_outs()[0];

    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"test",
        name: b"TxOut".to_vec(),
        is_completed: true,
        elems: vec![
            ASTNode::from(ASTAggregate {
                context: b"amount",
                name: b"Amount".to_vec(),
                is_completed: true,
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"commitment",
                        type_name: b"ristretto",
                        data: vec![
                            172, 16, 198, 12, 234, 63, 110, 222, 197, 110, 174, 61, 243, 236, 17,
                            137, 111, 17, 147, 46, 211, 210, 105, 25, 246, 234, 9, 139, 20, 165,
                            126, 122,
                        ],
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"masked_value",
                        type_name: b"uint",
                        data: vec![187, 146, 125, 76, 38, 34, 179, 187],
                    }),
                ],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"target_key",
                type_name: b"ristretto",
                data: vec![
                    126, 132, 117, 253, 124, 40, 56, 37, 230, 94, 15, 206, 138, 168, 124, 53, 160,
                    123, 163, 167, 130, 15, 16, 157, 171, 117, 12, 8, 214, 240, 105, 113,
                ],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"public_key",
                type_name: b"ristretto",
                data: vec![
                    238, 35, 140, 56, 133, 221, 101, 105, 2, 101, 249, 201, 51, 21, 57, 222, 41,
                    51, 60, 205, 41, 220, 180, 61, 236, 162, 72, 97, 136, 209, 89, 88,
                ],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"e_fog_hint",
                type_name: b"bytes",
                data: vec![
                    200, 11, 233, 27, 169, 243, 29, 190, 229, 212, 251, 154, 83, 218, 228, 86, 44,
                    229, 34, 224, 224, 95, 146, 9, 253, 162, 167, 75, 132, 164, 252, 102, 67, 184,
                    108, 150, 246, 214, 15, 106, 92, 189, 148, 227, 237, 135, 44, 121, 190, 52,
                    189, 0, 67, 68, 68, 248, 208, 231, 145, 194, 4, 77, 47, 49, 238, 63, 235, 28,
                    20, 201, 174, 217, 208, 221, 186, 140, 194, 244, 240, 69, 26, 77, 1, 0,
                ],
            }),
        ],
    });

    digestible_test_case_ast("test", tx_out, expected_ast);
}

#[test]
fn origin_block_digestible_ast() {
    let origin_tx_outs = test_origin_tx_outs();
    let origin = Block::new_origin_block(&origin_tx_outs[..]);

    let root_element_ast = ASTNode::from(ASTAggregate {
        context: b"root_element",
        name: b"TxOutMembershipElement".to_vec(),
        is_completed: true,
        elems: vec![
            ASTNode::from(ASTAggregate {
                context: b"range",
                name: b"Range".to_vec(),
                is_completed: true,
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"from",
                        type_name: b"uint",
                        data: vec![0; 8],
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"to",
                        type_name: b"uint",
                        data: vec![0; 8],
                    }),
                ],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"hash",
                type_name: b"bytes",
                data: vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            }),
        ],
    });

    digestible_test_case_ast(
        "root_element",
        &origin.root_element,
        root_element_ast.clone(),
    );

    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"test",
        name: b"Block".to_vec(),
        is_completed: true,
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"id",
                type_name: b"bytes",
                data: vec![
                    239, 212, 254, 14, 99, 142, 120, 10, 162, 43, 240, 17, 174, 105, 108, 169, 88,
                    89, 125, 57, 251, 59, 5, 34, 198, 186, 252, 243, 205, 168, 132, 22,
                ],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"version",
                type_name: b"uint",
                data: vec![0; 4],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"parent_id",
                type_name: b"bytes",
                data: vec![0; 32],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"index",
                type_name: b"uint",
                data: vec![0; 8],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"cumulative_txo_count",
                type_name: b"uint",
                data: vec![5, 0, 0, 0, 0, 0, 0, 0],
            }),
            root_element_ast,
            ASTNode::from(ASTPrimitive {
                context: b"contents_hash",
                type_name: b"bytes",
                data: vec![
                    4, 109, 35, 97, 243, 10, 38, 15, 175, 178, 67, 8, 197, 85, 85, 102, 238, 51,
                    51, 226, 100, 40, 117, 203, 72, 111, 39, 29, 80, 138, 125, 248,
                ],
            }),
        ],
    });

    digestible_test_case_ast("test", &origin, expected_ast);
}

#[test]
fn block_contents_digestible_test_vectors() {
    let results = test_blockchain(BlockVersion::ONE);

    // Test digest of block contents
    assert_eq!(
        results[0].1.hash().0,
        [
            141, 3, 218, 9, 245, 129, 12, 99, 192, 12, 107, 216, 4, 191, 254, 93, 247, 103, 110,
            204, 77, 126, 154, 187, 198, 139, 58, 24, 191, 179, 59, 125
        ]
    );
    assert_eq!(
        results[1].1.hash().0,
        [
            254, 230, 153, 200, 129, 98, 221, 154, 120, 76, 165, 230, 183, 128, 60, 26, 202, 64,
            171, 237, 164, 209, 9, 170, 109, 54, 133, 143, 110, 215, 199, 69
        ]
    );
    assert_eq!(
        results[2].1.hash().0,
        [
            215, 120, 30, 77, 126, 121, 230, 151, 225, 205, 247, 66, 101, 113, 221, 32, 122, 41,
            29, 53, 98, 48, 72, 183, 219, 255, 228, 161, 47, 46, 245, 221
        ]
    );

    let results = test_blockchain(BlockVersion::ZERO);

    // Test digest of block contents
    assert_eq!(
        results[0].1.hash().0,
        [
            127, 243, 87, 10, 229, 29, 137, 126, 255, 243, 163, 147, 39, 214, 116, 139, 171, 229,
            167, 113, 37, 54, 91, 191, 40, 244, 194, 114, 234, 189, 209, 239
        ]
    );
    assert_eq!(
        results[1].1.hash().0,
        [
            62, 59, 155, 219, 6, 106, 54, 48, 148, 22, 117, 39, 251, 161, 22, 50, 158, 7, 5, 104,
            182, 182, 7, 2, 156, 24, 0, 200, 68, 170, 76, 242
        ]
    );
    assert_eq!(
        results[2].1.hash().0,
        [
            53, 232, 155, 149, 47, 46, 234, 121, 250, 246, 126, 205, 173, 120, 62, 205, 224, 123,
            184, 44, 121, 7, 178, 128, 119, 190, 55, 127, 48, 69, 78, 77
        ]
    );
}
