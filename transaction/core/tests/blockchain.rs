use mc_account_keys::AccountKey;
use mc_transaction_core::{Block, BlockContents};

#[test]
fn test_cumulative_txo_counts() {
    mc_util_test_helper::run_with_several_seeds(|mut rng| {
        let origin = Block::new_origin_block(&[]);

        let accounts: Vec<AccountKey> = (0..20).map(|_i| AccountKey::random(&mut rng)).collect();
        let recipient_pub_keys = accounts
            .iter()
            .map(|account| account.default_subaddress())
            .collect::<Vec<_>>();

        let results: Vec<(Block, BlockContents)> = mc_transaction_core_test_utils::get_blocks(
            &recipient_pub_keys[..],
            1,
            50,
            50,
            &origin,
            &mut rng,
        );

        let mut prev = origin.clone();
        for (block, block_contents) in &results {
            assert_eq!(
                block.cumulative_txo_count,
                prev.cumulative_txo_count + block_contents.outputs.len() as u64
            );
            assert_eq!(block.parent_id, prev.id);
            prev = block.clone();
        }
    })
}
