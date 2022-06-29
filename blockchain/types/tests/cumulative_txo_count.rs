use mc_blockchain_test_utils::get_blocks;
use mc_blockchain_types::{Block, BlockVersion};
use mc_util_test_helper::run_with_several_seeds;

#[test]
fn test_cumulative_txo_counts() {
    run_with_several_seeds(|mut rng| {
        for block_version in BlockVersion::iterator() {
            let origin = Block::new_origin_block(&[]);
            let num_tokens = if block_version.mixed_transactions_are_supported() {
                2
            } else {
                1
            };
            let results = get_blocks(
                block_version,
                5,
                2,
                num_tokens,
                2,
                42,
                origin.clone(),
                &mut rng,
            );

            let mut parent = origin;
            for block_data in results {
                let block = block_data.block();
                let block_txo_count = block_data.contents().outputs.len() as u64;
                assert_eq!(
                    block.cumulative_txo_count,
                    parent.cumulative_txo_count + block_txo_count
                );
                assert_eq!(block.parent_id, parent.id);
                parent = block.clone();
            }
        }
    })
}
