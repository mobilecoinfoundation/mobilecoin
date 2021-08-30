// Copyright (c) 2018-2021 The MobileCoin Foundation

// this pub-use ensures linkage
pub use mc_fog_ocall_oram_storage_untrusted::{
    allocate_oram_storage, checkin_oram_storage, checkout_oram_storage, release_oram_storage,
};
// TODO: this test should ideally be generic over ORAMStorage trait, and part of
// mc-oblivious repo
#[cfg(test)]
mod testing {
    use aligned_cmov::{typenum, A64Bytes, A8Bytes, ArrayLength};
    use mc_fog_ocall_oram_storage_trusted::OcallORAMStorage;
    use mc_oblivious_traits::ORAMStorage;
    use mc_util_test_helper::run_with_several_seeds;
    use typenum::{U1024, U16};

    fn a64_bytes<N: ArrayLength<u8>>(src: u8) -> A64Bytes<N> {
        let mut result = A64Bytes::<N>::default();
        for byte in result.as_mut_slice() {
            *byte = src;
        }
        result
    }

    fn a8_bytes<N: ArrayLength<u8>>(src: u8) -> A8Bytes<N> {
        let mut result = A8Bytes::<N>::default();
        for byte in result.as_mut_slice() {
            *byte = src;
        }
        result
    }

    #[test]
    fn exercise_ocall_oram_storage() {
        run_with_several_seeds(|mut rng| {
            type StorageType = OcallORAMStorage<U1024, U16>;

            let mut st = StorageType::new(131072, &mut rng);

            let mut data_scratch = vec![A64Bytes::<U1024>::default(); 17];
            let mut meta_scratch = vec![A8Bytes::<U16>::default(); 17];

            // Write 1's along branch at 131072 - 1
            {
                st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

                // Initially the data might not be zeroed, but the meta must be
                for meta in meta_scratch.iter() {
                    assert_eq!(meta, &a8_bytes(0));
                }

                // Write to the data and metadata
                for data in data_scratch.iter_mut() {
                    *data = a64_bytes(1);
                }
                for meta in meta_scratch.iter_mut() {
                    *meta = a8_bytes(1);
                }

                st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
            }

            // Check that 1's are along branch at 131072 - 1
            {
                st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

                // Now both should be initialized
                for data in data_scratch.iter() {
                    assert_eq!(data, &a64_bytes(1));
                }
                for meta in meta_scratch.iter() {
                    assert_eq!(meta, &a8_bytes(1));
                }

                st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
            }

            // Write 2's along branch at 131072 - 4
            {
                st.checkout(131072 - 4, &mut data_scratch, &mut meta_scratch);

                // The first two data (lowest in branch) might not be initialized
                assert_eq!(data_scratch[0], a64_bytes(0));
                for data in &data_scratch[2..17] {
                    assert_eq!(data, &a64_bytes(1));
                }

                // The first two meta should be zeros
                assert_eq!(meta_scratch[0], a8_bytes(0));
                assert_eq!(meta_scratch[1], a8_bytes(0));
                for meta in &meta_scratch[2..] {
                    assert_eq!(meta, &a8_bytes(1));
                }

                // write 2's
                for data in data_scratch.iter_mut() {
                    *data = a64_bytes(2);
                }
                for meta in meta_scratch.iter_mut() {
                    *meta = a8_bytes(2);
                }

                st.checkin(131072 - 4, &mut data_scratch, &mut meta_scratch);
            }

            // Check that the 2's are visible along branch 131072 - 1, and some 1's
            {
                st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

                // the first two data should be 1's
                assert_eq!(data_scratch[0], a64_bytes(1));
                assert_eq!(data_scratch[1], a64_bytes(1));
                for data in &data_scratch[2..] {
                    assert_eq!(data, &a64_bytes(2));
                }

                // the first two meta should be 1's
                assert_eq!(meta_scratch[0], a8_bytes(1));
                assert_eq!(meta_scratch[1], a8_bytes(1));
                for meta in &meta_scratch[2..] {
                    assert_eq!(meta, &a8_bytes(2));
                }

                st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
            }

            // Write 3's along branch 131072 / 2 + 1, and check if 1's and 2's are visible
            {
                st.checkout(131072 / 2 + 1, &mut data_scratch, &mut meta_scratch);

                assert_eq!(data_scratch[16], a64_bytes(2));
                assert_eq!(meta_scratch[16], a8_bytes(2));
                for meta in &meta_scratch[0..16] {
                    assert_eq!(meta, &a8_bytes(0));
                }

                // write 3's
                for data in data_scratch.iter_mut() {
                    *data = a64_bytes(3);
                }
                for meta in meta_scratch.iter_mut() {
                    *meta = a8_bytes(3);
                }

                st.checkin(131072 / 2 + 1, &mut data_scratch, &mut meta_scratch);
            }

            // Check that 3's are along branch at 131072/2 + 1
            {
                st.checkout(131072 / 2 + 1, &mut data_scratch, &mut meta_scratch);

                for data in data_scratch.iter() {
                    assert_eq!(data, &a64_bytes(3));
                }
                for meta in meta_scratch.iter() {
                    assert_eq!(meta, &a8_bytes(3));
                }

                st.checkin(131072 / 2 + 1, &mut data_scratch, &mut meta_scratch);
            }

            // Check that 1's, 2's and 3's are visible along branch 131072 - 1
            {
                st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

                // the first two data should be 1's
                assert_eq!(data_scratch[0], a64_bytes(1));
                assert_eq!(data_scratch[1], a64_bytes(1));
                for data in &data_scratch[2..16] {
                    assert_eq!(data, &a64_bytes(2));
                }
                // this 3 at the root should be visible
                assert_eq!(data_scratch[16], a64_bytes(3));

                // the first two meta should be 1's
                assert_eq!(meta_scratch[0], a8_bytes(1));
                assert_eq!(meta_scratch[1], a8_bytes(1));
                for meta in &meta_scratch[2..16] {
                    assert_eq!(meta, &a8_bytes(2));
                }
                // this 3 at the root should be visible
                assert_eq!(meta_scratch[16], a8_bytes(3));

                st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
            }
        })
    }
}
