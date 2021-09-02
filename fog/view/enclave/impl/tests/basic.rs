// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::str::FromStr;
use mc_common::{
    logger::{test_with_logger, Logger},
    ResponderId,
};
use mc_fog_types::ETxOutRecord;
use mc_fog_view_enclave_api::{ViewEnclaveApi, ViewEnclaveInitParams};
use mc_fog_view_enclave_impl::ViewEnclave;
use mc_oblivious_traits::HeapORAMStorageCreator;

#[test_with_logger]
fn basic(logger: Logger) {
    let enclave = ViewEnclave::<HeapORAMStorageCreator>::new(logger);

    let params = ViewEnclaveInitParams {
        eid: 0,
        self_client_id: ResponderId::from_str("abc:123").unwrap(),
        desired_capacity: 1024 * 1024,
    };

    enclave.init(params).unwrap();

    // This was extracted from debugging of FOG-267 crash report
    let rec = ETxOutRecord {
        search_key: vec![
            159, 68, 24, 95, 144, 37, 158, 236, 147, 156, 105, 60, 48, 152, 7, 175,
        ],
        payload: vec![
            210, 74, 61, 135, 225, 207, 174, 95, 26, 75, 99, 254, 181, 1, 75, 147, 166, 106, 224,
            240, 79, 128, 23, 96, 236, 54, 80, 208, 145, 123, 97, 159, 106, 115, 209, 21, 153, 24,
            138, 173, 190, 124, 204, 160, 68, 92, 13, 167, 80, 136, 146, 119, 143, 210, 20, 83, 95,
            159, 196, 40, 22, 72, 172, 220, 177, 84, 161, 160, 179, 167, 136, 33, 202, 101, 200,
            24, 79, 100, 151, 125, 12, 246, 103, 149, 57, 103, 52, 87, 219, 18, 70, 167, 34, 248,
            243, 28, 111, 178, 33, 100, 209, 132, 90, 246, 151, 139, 248, 224, 37, 211, 158, 113,
            100, 165, 106, 22, 148, 31, 122, 9, 16, 217, 217, 109, 106, 142, 198, 74, 22, 142, 107,
            177, 106, 202, 6, 62, 93, 162, 173, 96, 45, 207, 0, 94, 140, 182, 169, 68, 1, 241, 161,
            58, 26, 230, 207, 243, 246, 203, 63, 243, 248, 60, 237, 9, 78, 59, 158, 217, 233, 14,
            244, 103, 157, 254, 62, 164, 38, 78, 14, 179, 49, 208, 137, 142, 105, 110, 146, 132,
            224, 189, 18, 148, 55, 8, 163, 43, 57, 107, 201, 3, 87, 1, 0,
        ],
    };

    enclave.add_records(vec![rec]).unwrap();
}
