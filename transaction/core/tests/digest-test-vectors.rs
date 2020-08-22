use mc_account_keys::AccountKey;
use mc_crypto_digestible_test_utils::*;
use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_core::{encrypted_fog_hint::EncryptedFogHint, tx::TxOut, Block, BlockContents};
use mc_util_from_random::FromRandom;
use rand_core::{RngCore, SeedableRng};
use rand_hc::Hc128Rng as FixedRng;

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
                rng.next_u32() as u64,
                &acct.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                EncryptedFogHint::fake_onetime_hint(&mut rng),
                &mut rng,
            )
            .unwrap()
        })
        .collect()
}

fn test_blockchain() -> Vec<(Block, BlockContents)> {
    let mut rng: FixedRng = SeedableRng::from_seed([10u8; 32]);

    let origin_tx_outs = test_origin_tx_outs();
    let origin = Block::new_origin_block(&origin_tx_outs[..]);
    let accounts = test_accounts();
    let recipient_pub_keys = accounts
        .iter()
        .map(|account| account.default_subaddress())
        .collect::<Vec<_>>();

    mc_transaction_core_test_utils::get_blocks(
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
                            242, 152, 40, 146, 146, 42, 240, 192, 35, 99, 79, 54, 220, 236, 108,
                            181, 213, 143, 214, 94, 153, 71, 189, 181, 22, 77, 172, 211, 204, 73,
                            63, 3,
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
                context: b"e_account_hint",
                type_name: b"bytes",
                data: vec![
                    165, 234, 17, 98, 158, 70, 82, 80, 174, 54, 135, 135, 107, 141, 215, 81, 56,
                    69, 162, 101, 225, 237, 184, 140, 10, 219, 123, 17, 207, 187, 210, 165, 66,
                    245, 105, 183, 136, 31, 101, 233, 86, 191, 35, 6, 42, 81, 44, 59, 246, 77, 18,
                    141, 90, 67, 169, 243, 2, 56, 101, 10, 2, 55, 212, 240, 173, 69, 76, 136, 133,
                    105, 181, 252, 11, 22, 207, 187, 106, 149, 108, 150, 246, 214, 15, 106, 92,
                    189, 148, 227, 237, 135, 44, 121, 190, 52, 189, 0, 67, 68, 68, 248, 208, 231,
                    145, 194, 4, 77, 47, 49, 238, 63, 73, 195, 126, 92, 230, 175, 136, 76, 47, 237,
                    65, 50, 107, 139, 225, 12, 0, 0,
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
                    138, 161, 54, 74, 202, 243, 220, 127, 18, 223, 79, 47, 175, 248, 56, 118, 93,
                    203, 45, 96, 32, 111, 2, 177, 99, 85, 125, 216, 81, 32, 223, 120,
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
                    142, 234, 222, 1, 66, 175, 228, 166, 18, 94, 58, 74, 199, 168, 43, 52, 175, 1,
                    126, 90, 222, 153, 120, 59, 217, 187, 215, 47, 43, 213, 93, 67,
                ],
            }),
        ],
    });

    digestible_test_case_ast("test", &origin, expected_ast);
}

#[test]
fn block_contents_digestible_test_vectors() {
    let results = test_blockchain();

    // Test digest of block contents
    assert_eq!(
        results[0].1.hash().0,
        [
            240, 248, 39, 213, 238, 139, 179, 52, 66, 98, 228, 213, 98, 181, 249, 230, 105, 202,
            218, 110, 172, 159, 85, 107, 7, 195, 167, 182, 136, 32, 118, 225
        ]
    );
    assert_eq!(
        results[1].1.hash().0,
        [
            67, 253, 132, 153, 88, 211, 167, 0, 229, 101, 235, 138, 136, 126, 77, 166, 4, 120, 181,
            65, 46, 248, 21, 92, 147, 246, 224, 17, 64, 177, 24, 212
        ]
    );
    assert_eq!(
        results[2].1.hash().0,
        [
            44, 13, 57, 132, 236, 228, 191, 151, 181, 46, 14, 162, 18, 204, 127, 110, 174, 21, 130,
            80, 20, 37, 193, 200, 145, 194, 55, 111, 71, 107, 39, 43
        ]
    );
}
