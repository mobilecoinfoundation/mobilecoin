// Copyright (c) 2018-2021 The MobileCoin Foundation
//
// Contains helper methods that enable conversions for Fog Api types.

use crate::fog_common;
use mc_fog_types::common;

impl From<&common::BlockRange> for fog_common::BlockRange {
    fn from(common_block_range: &common::BlockRange) -> fog_common::BlockRange {
        let mut proto_block_range = fog_common::BlockRange::new();
        proto_block_range.start_block = common_block_range.start_block;
        proto_block_range.end_block = common_block_range.end_block;

        proto_block_range
    }
}
