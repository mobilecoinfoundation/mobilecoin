// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_account_keys::AccountKey;
use mc_blockchain_test_utils::get_blocks_with_recipients;
use mc_blockchain_types::{Block, BlockVersion};
use mc_crypto_digestible_test_utils::*;
use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint, tokens::Mob, tx::TxOut, Amount, Token,
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
            TxOut::new(
                BlockVersion::ZERO,
                Amount {
                    value: rng.next_u32() as u64,
                    token_id: Mob::ID,
                },
                &acct.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                EncryptedFogHint::fake_onetime_hint(&mut rng),
            )
            .expect("Could not create TxOut")
        })
        .collect()
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
    let origin = Block::new_origin_block(&test_origin_tx_outs());

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
                data: vec![0; 32],
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

fn test_blockchain(block_version: BlockVersion) -> Vec<[u8; 32]> {
    let origin_tx_outs = test_origin_tx_outs();
    let origin = Block::new_origin_block(&origin_tx_outs[..]);
    let accounts = test_accounts();
    let recipient_pub_keys = accounts
        .iter()
        .map(|account| account.default_subaddress())
        .collect::<Vec<_>>();

    let mut rng = FixedRng::from_seed([10u8; 32]);
    get_blocks_with_recipients(
        block_version,
        3,
        &recipient_pub_keys[..],
        1,
        50,
        50,
        origin,
        &mut rng,
    )
    .into_iter()
    .map(|block_data| {
        let hash = &block_data.block().contents_hash;
        assert_eq!(hash, &block_data.contents().hash());
        hash.0
    })
    .collect()
}

// Test digest of block contents at versions 0 and 1.
#[test]
fn block_contents_digestible_v0() {
    assert_eq!(
        test_blockchain(BlockVersion::ZERO),
        [
            [
                203, 245, 7, 219, 1, 210, 70, 210, 93, 109, 135, 251, 188, 10, 120, 155, 108, 240,
                18, 0, 89, 156, 18, 143, 136, 8, 169, 97, 25, 150, 178, 46
            ],
            [
                54, 192, 31, 97, 184, 133, 252, 77, 58, 179, 228, 251, 171, 126, 158, 75, 32, 84,
                82, 114, 115, 15, 162, 111, 252, 166, 179, 7, 181, 119, 177, 187
            ],
            [
                236, 60, 128, 45, 199, 115, 208, 199, 32, 82, 230, 193, 18, 127, 139, 221, 112,
                165, 191, 116, 8, 223, 88, 6, 247, 77, 238, 242, 185, 28, 59, 105
            ]
        ]
    );
}

#[test]
fn block_contents_digestible_v1() {
    assert_eq!(
        test_blockchain(BlockVersion::ONE),
        [
            [
                126, 82, 1, 40, 59, 4, 198, 138, 175, 164, 245, 37, 61, 87, 228, 167, 179, 164, 13,
                151, 165, 219, 177, 188, 30, 66, 116, 242, 46, 216, 148, 181
            ],
            [
                175, 203, 59, 69, 47, 106, 110, 92, 255, 130, 32, 232, 192, 153, 202, 46, 113, 186,
                181, 248, 84, 31, 233, 133, 162, 237, 83, 10, 23, 26, 218, 32
            ],
            [
                166, 180, 148, 136, 166, 248, 232, 243, 179, 83, 228, 35, 173, 193, 126, 139, 26,
                80, 174, 81, 115, 88, 40, 52, 124, 98, 184, 251, 71, 253, 152, 116
            ]
        ]
    );
}
