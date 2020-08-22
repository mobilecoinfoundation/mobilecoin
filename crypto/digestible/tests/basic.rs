// Copyright (c) 2018-2020 MobileCoin Inc.

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use mc_crypto_digestible::{Digestible, MerlinTranscript};

// Test merlin transcript hash values for various primitives
#[test]
fn primitives_test_vectors() {
    assert_eq!(
        u64::max_value().digest32::<MerlinTranscript>(b"test"),
        [
            199, 212, 113, 79, 91, 56, 22, 48, 131, 244, 165, 157, 170, 131, 255, 29, 59, 249, 175,
            89, 255, 57, 43, 50, 76, 217, 9, 219, 85, 103, 113, 88
        ]
    );
    assert_eq!(
        1u32.digest32::<MerlinTranscript>(b"test"),
        [
            145, 81, 95, 184, 130, 3, 242, 53, 64, 171, 131, 200, 129, 99, 61, 59, 62, 5, 167, 57,
            201, 221, 68, 223, 241, 12, 120, 3, 84, 230, 233, 57
        ]
    );
    assert_eq!(
        4u16.digest32::<MerlinTranscript>(b"test"),
        [
            162, 203, 81, 231, 249, 140, 154, 24, 65, 158, 148, 64, 96, 21, 48, 84, 126, 206, 225,
            124, 197, 61, 5, 150, 125, 45, 85, 113, 176, 112, 16, 74
        ]
    );
    assert_eq!(
        (-1i8).digest32::<MerlinTranscript>(b"test"),
        [
            228, 7, 115, 202, 168, 246, 222, 11, 56, 46, 232, 222, 2, 174, 19, 94, 172, 49, 183,
            58, 90, 36, 230, 25, 155, 70, 152, 91, 25, 32, 232, 134
        ]
    );
    assert_eq!(
        (-19i64).digest32::<MerlinTranscript>(b"test"),
        [
            40, 117, 43, 212, 193, 213, 3, 244, 43, 51, 234, 26, 235, 38, 254, 187, 55, 184, 30,
            147, 157, 178, 45, 2, 206, 64, 250, 109, 179, 41, 250, 207
        ]
    );
    assert_eq!(
        true.digest32::<MerlinTranscript>(b"test"),
        [
            43, 47, 123, 204, 127, 100, 113, 181, 186, 75, 237, 124, 118, 82, 178, 18, 36, 68, 200,
            197, 226, 119, 254, 216, 248, 169, 80, 213, 177, 105, 74, 139
        ]
    );
    assert_eq!(
        (&b"Moose"[..]).digest32::<MerlinTranscript>(b"test"),
        [
            74, 2, 88, 165, 144, 53, 142, 180, 217, 188, 176, 227, 153, 178, 153, 12, 62, 157, 215,
            120, 135, 160, 117, 114, 95, 201, 169, 182, 238, 153, 17, 21
        ]
    );
    assert_eq!(
        ("boffin".to_string()).digest32::<MerlinTranscript>(b"test"),
        [
            25, 163, 90, 30, 73, 203, 215, 3, 137, 163, 71, 92, 53, 242, 186, 58, 222, 248, 71,
            246, 123, 235, 51, 39, 52, 101, 247, 160, 90, 1, 169, 175
        ]
    );
    assert_eq!(
        Scalar::from(10u32).digest32::<MerlinTranscript>(b"test"),
        [
            174, 15, 64, 233, 225, 254, 36, 100, 145, 155, 193, 51, 53, 242, 199, 217, 148, 118,
            26, 152, 227, 191, 65, 98, 185, 116, 209, 84, 57, 190, 233, 197
        ]
    );
    assert_eq!(
        (Scalar::from(10u32) * RISTRETTO_BASEPOINT_POINT).digest32::<MerlinTranscript>(b"test"),
        [
            138, 144, 135, 180, 70, 213, 175, 162, 233, 19, 227, 66, 97, 189, 110, 31, 193, 8, 212,
            64, 245, 46, 118, 54, 118, 168, 115, 88, 160, 39, 243, 63
        ]
    );
    assert_eq!(
        vec![1u32, 2u32, 3u32].digest32::<MerlinTranscript>(b"test"),
        [
            57, 188, 233, 215, 161, 193, 239, 222, 47, 27, 96, 29, 63, 204, 63, 47, 197, 53, 50,
            58, 62, 148, 55, 17, 109, 143, 127, 120, 19, 50, 44, 18
        ]
    );
}

// Test digesting of Option
#[test]
fn test_digest_option() {
    let temp: Option<u64> = None;
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            35, 213, 109, 195, 226, 235, 162, 166, 228, 183, 30, 23, 226, 184, 19, 8, 12, 166, 24,
            194, 247, 84, 216, 45, 122, 19, 75, 140, 159, 233, 85, 6
        ]
    );
    let temp: Option<u64> = Some(u64::max_value());
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        u64::max_value().digest32::<MerlinTranscript>(b"test")
    );
}

// Test digesting of Vec
#[test]
fn test_digest_vec() {
    let temp: Vec<u64> = Default::default();
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            35, 213, 109, 195, 226, 235, 162, 166, 228, 183, 30, 23, 226, 184, 19, 8, 12, 166, 24,
            194, 247, 84, 216, 45, 122, 19, 75, 140, 159, 233, 85, 6
        ]
    );
    let temp: Vec<u64> = vec![1, 2, 3];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            24, 143, 163, 51, 160, 229, 9, 222, 149, 104, 49, 33, 194, 75, 205, 201, 10, 100, 27,
            224, 134, 252, 82, 178, 105, 246, 138, 217, 42, 232, 222, 58
        ]
    );
}

// Test digesting of Vec<Option>
#[test]
fn test_digest_vec_option() {
    let temp: Vec<Option<String>> = Default::default();
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            35, 213, 109, 195, 226, 235, 162, 166, 228, 183, 30, 23, 226, 184, 19, 8, 12, 166, 24,
            194, 247, 84, 216, 45, 122, 19, 75, 140, 159, 233, 85, 6
        ]
    );
    let temp: Vec<Option<String>> = vec![
        Some("asdf".to_string()),
        Some("jkl".to_string()),
        Some(";".to_string()),
    ];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            26, 88, 109, 42, 55, 246, 243, 204, 73, 111, 147, 205, 172, 136, 195, 221, 105, 185,
            60, 203, 215, 47, 226, 114, 104, 103, 110, 76, 122, 85, 146, 203
        ]
    );

    let temp: Vec<Option<String>> = vec![Some("asdf".to_string()), None, Some("jkl".to_string())];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            216, 197, 219, 123, 74, 59, 155, 97, 23, 51, 16, 187, 15, 18, 43, 165, 36, 166, 89, 49,
            103, 111, 139, 68, 35, 50, 146, 153, 49, 205, 196, 76
        ]
    );

    let temp: Vec<Option<String>> = vec![Some("asdf".to_string()), Some("jkl".to_string()), None];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            25, 170, 89, 13, 170, 73, 17, 193, 186, 141, 113, 184, 253, 240, 35, 176, 33, 247, 114,
            134, 236, 121, 191, 74, 108, 39, 203, 152, 153, 152, 98, 200
        ]
    );

    let temp: Vec<Option<String>> = vec![None, Some("asdf".to_string()), Some("jkl".to_string())];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            69, 118, 173, 141, 229, 181, 42, 28, 35, 209, 78, 216, 80, 233, 89, 37, 20, 89, 119,
            81, 155, 248, 41, 15, 188, 229, 29, 93, 185, 189, 245, 59
        ]
    );

    let temp: Vec<Option<String>> = vec![None, Some("jkl".to_string()), Some("asdf".to_string())];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            177, 75, 168, 78, 81, 222, 158, 166, 198, 245, 235, 226, 158, 206, 239, 247, 22, 69,
            41, 223, 241, 223, 41, 86, 165, 166, 56, 120, 221, 175, 56, 138
        ]
    );

    let temp: Vec<Option<String>> = vec![Some("jkl".to_string()), None, Some("asdf".to_string())];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            95, 219, 199, 189, 16, 90, 230, 246, 244, 144, 245, 81, 94, 207, 98, 250, 203, 25, 45,
            224, 203, 198, 158, 199, 96, 181, 53, 238, 94, 135, 158, 137
        ]
    );

    let temp: Vec<Option<String>> = vec![None, Some("asdf".to_string()), None];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            103, 138, 24, 132, 46, 32, 144, 112, 53, 150, 104, 143, 236, 144, 68, 63, 156, 43, 48,
            237, 40, 227, 243, 53, 115, 68, 203, 180, 62, 12, 213, 86
        ]
    );

    let temp: Vec<Option<String>> = vec![None, None, Some("asdf".to_string())];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            130, 16, 160, 220, 41, 97, 72, 142, 69, 124, 7, 22, 131, 88, 92, 249, 17, 46, 104, 97,
            215, 142, 128, 195, 220, 165, 51, 84, 64, 170, 0, 98
        ]
    );

    let temp: Vec<Option<String>> = vec![Some("asdf".to_string()), None, None];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            208, 24, 155, 139, 114, 50, 177, 149, 247, 47, 2, 222, 246, 101, 98, 40, 239, 174, 180,
            82, 147, 153, 32, 182, 134, 103, 160, 237, 149, 178, 117, 73
        ]
    );

    let temp: Vec<Option<String>> = vec![None, None, None];
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            8, 18, 95, 143, 25, 20, 150, 144, 72, 62, 133, 192, 108, 99, 204, 112, 251, 94, 58, 78,
            107, 220, 65, 193, 92, 148, 134, 86, 198, 239, 101, 29
        ]
    );
}

// Test digesting of Option<Vec>
#[test]
fn test_digest_option_vec() {
    let temp: Option<Vec<String>> = Default::default();
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            35, 213, 109, 195, 226, 235, 162, 166, 228, 183, 30, 23, 226, 184, 19, 8, 12, 166, 24,
            194, 247, 84, 216, 45, 122, 19, 75, 140, 159, 233, 85, 6
        ]
    );

    let temp: Option<Vec<String>> = Some(Default::default());
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            35, 213, 109, 195, 226, 235, 162, 166, 228, 183, 30, 23, 226, 184, 19, 8, 12, 166, 24,
            194, 247, 84, 216, 45, 122, 19, 75, 140, 159, 233, 85, 6
        ]
    );

    let temp: Option<Vec<String>> = Some(vec!["".to_string()]);
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            106, 97, 242, 241, 157, 115, 144, 207, 35, 28, 134, 236, 118, 204, 13, 90, 213, 247,
            75, 84, 97, 9, 249, 103, 204, 156, 73, 116, 43, 107, 2, 50
        ]
    );

    let temp: Option<Vec<String>> = Some(vec!["".to_string(), "".to_string()]);
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            146, 81, 250, 209, 154, 170, 143, 197, 106, 225, 13, 53, 65, 43, 149, 160, 40, 208, 95,
            252, 171, 198, 29, 25, 16, 115, 8, 181, 204, 141, 53, 190
        ]
    );

    let temp: Option<Vec<String>> = Some(vec!["a".to_string(), "".to_string()]);
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            77, 83, 0, 35, 200, 194, 224, 46, 115, 82, 91, 201, 237, 38, 45, 84, 141, 57, 237, 210,
            145, 124, 202, 8, 183, 232, 133, 154, 64, 138, 113, 129
        ]
    );
}

// Test digesting of BTreeSet
#[test]
fn test_btree_set() {
    let mut temp: std::collections::BTreeSet<String> = Default::default();
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            35, 213, 109, 195, 226, 235, 162, 166, 228, 183, 30, 23, 226, 184, 19, 8, 12, 166, 24,
            194, 247, 84, 216, 45, 122, 19, 75, 140, 159, 233, 85, 6
        ]
    );

    temp.insert("grand poobah".to_string());
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            210, 136, 34, 38, 213, 185, 137, 120, 159, 54, 137, 226, 230, 4, 75, 207, 140, 148, 12,
            236, 159, 185, 118, 204, 5, 92, 220, 136, 158, 205, 152, 193
        ]
    );

    temp.insert("fannypack".to_string());
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            108, 250, 45, 200, 115, 214, 121, 56, 156, 2, 25, 226, 223, 181, 224, 194, 97, 31, 33,
            0, 187, 10, 183, 78, 38, 125, 68, 149, 1, 113, 226, 96
        ]
    );

    temp.insert("zirconium".to_string());
    assert_eq!(
        temp.digest32::<MerlinTranscript>(b"test"),
        [
            176, 47, 111, 203, 159, 113, 28, 219, 6, 63, 115, 125, 48, 45, 122, 216, 233, 127, 181,
            232, 23, 255, 26, 220, 120, 2, 44, 218, 67, 3, 64, 137
        ]
    );
}

// Test digesting of Generic Array
#[test]
fn test_generic_array() {
    use generic_array::arr;

    let array = [1u8, 2u8, 3u8];
    let garray = arr![u8; 1, 2, 3];
    assert_eq!(
        array.digest32::<MerlinTranscript>(b"test"),
        garray.digest32::<MerlinTranscript>(b"test"),
    );
}
