// Copyright (c) 2018-2022 The MobileCoin Foundation

/// Tests of the schema evolution properties of derive(Digestible)
/// implementations when transparent enums are involved
use mc_crypto_digestible::Digestible;
use mc_crypto_digestible_test_utils::*;

// An example structure
#[derive(Digestible)]
struct Thing {
    a: u64,
    b: u64,
}

// One of the fields is changed into an enum
#[derive(Digestible)]
#[digestible(transparent)]
enum Switch {
    Num(u64),
    Str(String),
}

#[derive(Digestible)]
#[digestible(name = "Thing")]
struct ThingV2 {
    a: u64,
    b: Switch,
}

// A new, empty, state is added to the enum
#[derive(Digestible)]
#[digestible(transparent)]
enum SwitchV2 {
    Num(u64),
    Str(String),
    Empty,
}

#[derive(Digestible)]
#[digestible(name = "Thing")]
struct ThingV3 {
    a: u64,
    b: SwitchV2,
}

// A new field is added to the struct using the transparent enum. This does not
// break hash compatibility because an empty state in a transparent enum is
// treated similarly to Option::None, and nothing gets added to the hash to
// represent it. So this is similar to adding an optional field.
#[derive(Digestible)]
#[digestible(name = "Thing")]
struct ThingV4 {
    a: u64,
    b: SwitchV2,
    c: SwitchV2,
}

// Tests for struct schema evolution using transparent enums
#[test]
fn transparent_enum_schema_evolution() {
    assert_eq!(
        calculate_digest_ast(b"test", &Thing { a: 7, b: 4 }),
        calculate_digest_ast(
            b"test",
            &ThingV2 {
                a: 7,
                b: Switch::Num(4)
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(
            b"test",
            &ThingV2 {
                a: 7,
                b: Switch::Num(4)
            }
        ),
        calculate_digest_ast(
            b"test",
            &ThingV3 {
                a: 7,
                b: SwitchV2::Num(4),
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(
            b"test",
            &ThingV2 {
                a: 7,
                b: Switch::Str("foo".into())
            }
        ),
        calculate_digest_ast(
            b"test",
            &ThingV3 {
                a: 7,
                b: SwitchV2::Str("foo".into()),
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(b"test", &Thing { a: 7, b: 9 }),
        calculate_digest_ast(
            b"test",
            &ThingV3 {
                a: 7,
                b: SwitchV2::Num(9),
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(
            b"test",
            &ThingV2 {
                a: 7,
                b: Switch::Num(8)
            }
        ),
        calculate_digest_ast(
            b"test",
            &ThingV4 {
                a: 7,
                b: SwitchV2::Num(8),
                c: SwitchV2::Empty,
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(
            b"test",
            &ThingV2 {
                a: 7,
                b: Switch::Str("foo".into())
            }
        ),
        calculate_digest_ast(
            b"test",
            &ThingV4 {
                a: 7,
                b: SwitchV2::Str("foo".into()),
                c: SwitchV2::Empty,
            }
        )
    );
}
