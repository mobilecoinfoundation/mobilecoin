// Copyright (c) 2018-2020 MobileCoin Inc.

/// Test that mc_util_build_info::write_report produces valid json
#[test]
fn build_info_report_json() {
    let mut buf = String::new();
    mc_util_build_info::write_report(&mut buf).unwrap();

    json::parse(&buf).unwrap();
}
