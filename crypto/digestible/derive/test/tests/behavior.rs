// Copyright (c) 2018-2020 MobileCoin Inc.

/// Tests against the behavior of the generated Digestible traits
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_digestible_test_utils::*;

// Test structs
#[derive(Digestible)]
struct Foo {
    a: u16,
    b: u16,
    c: u16,
}

#[derive(Digestible)]
struct Blob(Vec<u8>);

#[derive(Digestible)]
#[digestible(transparent)]
struct TransBlob(Vec<u8>);

#[derive(Digestible)]
struct Bar {
    d: Blob,
    e: u32,
    f: Foo,
}

#[derive(Digestible)]
struct TBar {
    d: TransBlob,
    e: u32,
    f: Foo,
}

#[derive(Digestible)]
struct GenericFoo<X: Digestible> {
    a: X,
    b: X,
}

#[test]
fn foo1() {
    let arg = Foo { a: 0, b: 1, c: 2 };
    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"foo1",
        name: b"Foo".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"a",
                type_name: b"uint",
                data: vec![0u8, 0u8],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"b",
                type_name: b"uint",
                data: vec![1u8, 0u8],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"c",
                type_name: b"uint",
                data: vec![2u8, 0u8],
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("foo1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"foo1"),
        [
            44, 174, 200, 201, 207, 72, 151, 193, 63, 97, 49, 112, 135, 50, 252, 61, 211, 208, 41,
            4, 241, 249, 90, 114, 181, 197, 177, 151, 39, 165, 76, 197
        ]
    );
}

#[test]
fn blob1() {
    let arg = Blob(vec![1, 2, 3, 4]);
    let expected_ast = ASTNode::Aggregate(ASTAggregate {
        context: b"blob1",
        name: b"Blob".to_vec(),
        elems: vec![ASTNode::Primitive(ASTPrimitive {
            context: b"0",
            type_name: b"bytes",
            data: vec![1u8, 2u8, 3u8, 4u8],
        })],
        is_completed: true,
    });
    digestible_test_case_ast("blob1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"blob1"),
        [
            59, 63, 205, 99, 4, 221, 221, 230, 90, 1, 135, 226, 106, 52, 210, 105, 88, 37, 182, 26,
            208, 240, 152, 4, 226, 0, 204, 11, 10, 187, 14, 48
        ]
    );
}

#[test]
fn blob2() {
    let arg = TransBlob(vec![1, 2, 3, 4]);
    let expected_ast = ASTNode::Primitive(ASTPrimitive {
        context: b"blob2",
        type_name: b"bytes",
        data: vec![1u8, 2u8, 3u8, 4u8],
    });
    digestible_test_case_ast("blob2", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"blob2"),
        [
            221, 88, 184, 210, 180, 30, 40, 40, 89, 37, 221, 90, 185, 33, 199, 133, 99, 102, 67,
            196, 197, 85, 67, 234, 151, 160, 111, 230, 234, 125, 181, 1
        ]
    );
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"blob2"),
        vec![1u8, 2u8, 3u8, 4u8].digest32::<MerlinTranscript>(b"blob2")
    );
}

#[test]
fn bar1() {
    let arg = Bar {
        d: Blob(b"Koala".to_vec()),
        e: u32::max_value(),
        f: Foo { a: 5, b: 6, c: 7 },
    };
    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"bar1",
        name: b"Bar".to_vec(),
        elems: vec![
            ASTNode::from(ASTAggregate {
                context: b"d",
                name: b"Blob".to_vec(),
                elems: vec![ASTNode::from(ASTPrimitive {
                    context: b"0",
                    type_name: b"bytes",
                    data: b"Koala".to_vec(),
                })],
                is_completed: true,
            }),
            ASTNode::from(ASTPrimitive {
                context: b"e",
                type_name: b"uint",
                data: vec![255u8; 4],
            }),
            ASTNode::from(ASTAggregate {
                context: b"f",
                name: b"Foo".to_vec(),
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"a",
                        type_name: b"uint",
                        data: vec![5u8, 0u8],
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"b",
                        type_name: b"uint",
                        data: vec![6u8, 0u8],
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"c",
                        type_name: b"uint",
                        data: vec![7u8, 0u8],
                    }),
                ],
                is_completed: true,
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("bar1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"bar1"),
        [
            237, 231, 204, 138, 55, 249, 219, 0, 154, 213, 236, 77, 123, 104, 185, 68, 165, 117,
            179, 15, 85, 65, 13, 134, 163, 16, 206, 60, 249, 184, 194, 81
        ]
    );
}

#[test]
fn bar2() {
    let arg = TBar {
        d: TransBlob(b"Koala".to_vec()),
        e: u32::max_value(),
        f: Foo { a: 5, b: 6, c: 7 },
    };
    let expected_ast = ASTNode::Aggregate(ASTAggregate {
        context: b"bar2",
        name: b"TBar".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"d",
                type_name: b"bytes",
                data: b"Koala".to_vec(),
            }),
            ASTNode::from(ASTPrimitive {
                context: b"e",
                type_name: b"uint",
                data: vec![255u8; 4],
            }),
            ASTNode::from(ASTAggregate {
                context: b"f",
                name: b"Foo".to_vec(),
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"a",
                        type_name: b"uint",
                        data: vec![5u8, 0u8],
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"b",
                        type_name: b"uint",
                        data: vec![6u8, 0u8],
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"c",
                        type_name: b"uint",
                        data: vec![7u8, 0u8],
                    }),
                ],
                is_completed: true,
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("bar2", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"bar2"),
        [
            145, 7, 120, 187, 254, 152, 10, 160, 109, 154, 97, 187, 141, 79, 168, 83, 228, 12, 11,
            66, 79, 131, 15, 169, 231, 200, 214, 196, 154, 23, 190, 107
        ]
    );
}

#[test]
fn generic_foo1() {
    let arg = GenericFoo {
        a: 123 as u32,
        b: 456 as u32,
    };

    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"genfoo1",
        name: b"GenericFoo".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"a",
                type_name: b"uint",
                data: 123u32.to_le_bytes().to_vec(),
            }),
            ASTNode::from(ASTPrimitive {
                context: b"b",
                type_name: b"uint",
                data: 456u32.to_le_bytes().to_vec(),
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("genfoo1", &arg, expected_ast.clone());
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"genfoo1"),
        [
            194, 207, 55, 95, 52, 136, 167, 235, 136, 171, 231, 204, 239, 42, 41, 163, 56, 87, 130,
            74, 1, 23, 20, 98, 33, 36, 3, 82, 31, 91, 104, 94
        ]
    );

    let arg2 = GenericFoo {
        a: Some(123 as u32),
        b: Some(456 as u32),
    };

    digestible_test_case_ast("genfoo1", &arg2, expected_ast);
    assert_eq!(
        arg2.digest32::<MerlinTranscript>(b"genfoo1"),
        [
            194, 207, 55, 95, 52, 136, 167, 235, 136, 171, 231, 204, 239, 42, 41, 163, 56, 87, 130,
            74, 1, 23, 20, 98, 33, 36, 3, 82, 31, 91, 104, 94
        ]
    );
}

#[test]
fn generic_foo2() {
    let arg = GenericFoo {
        a: String::from("str1"),
        b: String::from("str2"),
    };

    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"genfoo2",
        name: b"GenericFoo".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"a",
                type_name: b"str",
                data: "str1".as_bytes().to_vec(),
            }),
            ASTNode::from(ASTPrimitive {
                context: b"b",
                type_name: b"str",
                data: "str2".as_bytes().to_vec(),
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("genfoo2", &arg, expected_ast.clone());
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"genfoo2"),
        [
            73, 146, 142, 113, 190, 93, 124, 188, 118, 21, 72, 51, 19, 101, 141, 43, 101, 207, 234,
            146, 65, 49, 191, 0, 40, 215, 129, 168, 55, 80, 189, 247
        ]
    );

    let arg2 = GenericFoo {
        a: Some(String::from("str1")),
        b: Some(String::from("str2")),
    };

    digestible_test_case_ast("genfoo2", &arg2, expected_ast);
    assert_eq!(
        arg2.digest32::<MerlinTranscript>(b"genfoo2"),
        [
            73, 146, 142, 113, 190, 93, 124, 188, 118, 21, 72, 51, 19, 101, 141, 43, 101, 207, 234,
            146, 65, 49, 191, 0, 40, 215, 129, 168, 55, 80, 189, 247
        ]
    );
}

// An example structure
#[derive(Digestible)]
struct Thing {
    a: u64,
}

// A new field is added which is marked optional
#[derive(Digestible)]
#[digestible(name = "Thing")]
struct ThingV2 {
    a: u64,
    b: Option<u64>,
}

// An old field which was not optional is marked optional
#[derive(Digestible)]
#[digestible(name = "Thing")]
struct ThingV3 {
    a: Option<u64>,
    b: Option<u64>,
}

// An new repeated field appears
#[derive(Digestible)]
#[digestible(name = "Thing")]
struct ThingV4 {
    a: Option<u64>,
    b: Option<u64>,
    c: Vec<bool>,
}

#[test]
fn thing_struct() {
    assert_eq!(
        Thing { a: 19 }.digest32::<MerlinTranscript>(b"thing"),
        [
            129, 172, 63, 2, 11, 236, 144, 45, 86, 222, 142, 172, 125, 149, 244, 67, 141, 193, 126,
            52, 249, 50, 226, 15, 239, 255, 253, 28, 212, 67, 215, 138
        ]
    );
    assert_eq!(
        ThingV2 { a: 19, b: Some(11) }.digest32::<MerlinTranscript>(b"thing"),
        [
            215, 162, 90, 161, 25, 42, 100, 213, 214, 162, 132, 209, 46, 150, 200, 229, 152, 101,
            152, 177, 103, 24, 152, 188, 51, 4, 26, 117, 184, 235, 117, 189
        ]
    );
    assert_eq!(
        ThingV4 {
            a: Some(19),
            b: None,
            c: vec![true, false]
        }
        .digest32::<MerlinTranscript>(b"thing"),
        [
            10, 34, 82, 129, 5, 30, 197, 99, 66, 246, 191, 25, 96, 23, 84, 249, 228, 156, 252, 247,
            30, 194, 152, 147, 221, 244, 220, 46, 23, 236, 213, 203
        ]
    );
}

// Tests for struct_schema evolution
#[test]
fn struct_schema_evolution() {
    assert_eq!(
        calculate_digest_ast(b"test", &Thing { a: 7 }),
        calculate_digest_ast(b"test", &ThingV2 { a: 7, b: None })
    );

    assert_eq!(
        calculate_digest_ast(b"test", &ThingV2 { a: 7, b: None }),
        calculate_digest_ast(
            b"test",
            &ThingV3 {
                a: Some(7),
                b: None
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(b"test", &ThingV2 { a: 7, b: Some(11) }),
        calculate_digest_ast(
            b"test",
            &ThingV3 {
                a: Some(7),
                b: Some(11)
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(
            b"test",
            &ThingV3 {
                a: Some(7),
                b: Some(11)
            }
        ),
        calculate_digest_ast(
            b"test",
            &ThingV4 {
                a: Some(7),
                b: Some(11),
                c: Default::default()
            }
        )
    );

    assert_eq!(
        Thing { a: 3 }.digest32::<MerlinTranscript>(b"test"),
        ThingV2 { a: 3, b: None }.digest32::<MerlinTranscript>(b"test")
    );

    assert_eq!(
        ThingV2 { a: 3, b: None }.digest32::<MerlinTranscript>(b"test"),
        ThingV3 {
            a: Some(3),
            b: None
        }
        .digest32::<MerlinTranscript>(b"test")
    );

    assert_eq!(
        Thing { a: 3 }.digest32::<MerlinTranscript>(b"test"),
        ThingV4 {
            a: Some(3),
            b: None,
            c: Default::default()
        }
        .digest32::<MerlinTranscript>(b"test")
    );

    assert_eq!(
        ThingV2 { a: 14, b: Some(99) }.digest32::<MerlinTranscript>(b"test"),
        ThingV3 {
            a: Some(14),
            b: Some(99)
        }
        .digest32::<MerlinTranscript>(b"test")
    );

    assert_eq!(
        ThingV2 { a: 14, b: Some(99) }.digest32::<MerlinTranscript>(b"test"),
        ThingV4 {
            a: Some(14),
            b: Some(99),
            c: Default::default()
        }
        .digest32::<MerlinTranscript>(b"test")
    );
}

// Tests for what happens in exotic cases, like Option<Option> and Option<Vec> that are less likely to happen
#[test]
fn thing_struct_exotic() {
    // b is made doubly optional
    #[derive(Digestible)]
    #[digestible(name = "Thing")]
    struct ThingV5 {
        a: Option<u64>,
        b: Option<Option<u64>>,
        c: Vec<bool>,
    }

    assert_eq!(
        calculate_digest_ast(b"test", &Thing { a: 7 }),
        calculate_digest_ast(
            b"test",
            &ThingV5 {
                a: Some(7),
                b: None,
                c: Default::default()
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(b"test", &Thing { a: 7 }),
        calculate_digest_ast(
            b"test",
            &ThingV5 {
                a: Some(7),
                b: Some(None),
                c: Default::default()
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(b"test", &ThingV2 { a: 7, b: Some(14) }),
        calculate_digest_ast(
            b"test",
            &ThingV5 {
                a: Some(7),
                b: Some(Some(14)),
                c: Default::default()
            }
        )
    );

    assert_eq!(
        ThingV5 {
            a: Some(19),
            b: Some(None),
            c: vec![true]
        }
        .digest32::<MerlinTranscript>(b"test"),
        [
            239, 194, 107, 94, 247, 46, 191, 177, 9, 15, 67, 114, 122, 77, 186, 13, 104, 61, 109,
            222, 169, 40, 137, 133, 136, 196, 75, 12, 144, 18, 239, 181
        ]
    );

    // c is made option<vec>
    #[derive(Digestible)]
    #[digestible(name = "Thing")]
    struct ThingV6 {
        a: Option<u64>,
        b: Option<u64>,
        c: Option<Vec<bool>>,
    }

    assert_eq!(
        calculate_digest_ast(b"test", &Thing { a: 7 }),
        calculate_digest_ast(
            b"test",
            &ThingV6 {
                a: Some(7),
                b: None,
                c: None
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(
            b"test",
            &ThingV6 {
                a: Some(7),
                b: None,
                c: None
            }
        ),
        calculate_digest_ast(
            b"test",
            &ThingV6 {
                a: Some(7),
                b: None,
                c: Some(Default::default())
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(b"test", &ThingV2 { a: 7, b: Some(14) }),
        calculate_digest_ast(
            b"test",
            &ThingV6 {
                a: Some(7),
                b: Some(14),
                c: None
            }
        )
    );

    assert_eq!(
        calculate_digest_ast(
            b"test",
            &ThingV6 {
                a: Some(7),
                b: Some(14),
                c: None
            }
        ),
        calculate_digest_ast(
            b"test",
            &ThingV6 {
                a: Some(7),
                b: Some(14),
                c: Some(Default::default())
            }
        )
    );

    assert_eq!(
        ThingV6 {
            a: Some(19),
            b: None,
            c: Some(vec![true])
        }
        .digest32::<MerlinTranscript>(b"test"),
        [
            239, 194, 107, 94, 247, 46, 191, 177, 9, 15, 67, 114, 122, 77, 186, 13, 104, 61, 109,
            222, 169, 40, 137, 133, 136, 196, 75, 12, 144, 18, 239, 181
        ]
    );
}

// A test enum, with a generic parameter
#[derive(Digestible)]
enum TestEnum<V: Digestible> {
    Option1,
    Option2(V),
    Option3(u32, String),
    Option4 { a: V, b: V },
}

// Test digesting an enum.
#[test]
fn test_digest_enum() {
    {
        let obj = TestEnum::<u64>::Option1;

        let expected_ast = ASTNode::from(ASTVariant {
            context: b"var1",
            name: b"TestEnum".to_vec(),
            which: 0,
            value: Some(Box::new(ASTNode::from(ASTNone {
                context: b"Option1",
            }))),
        });

        digestible_test_case_ast("var1", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var1"),
            [
                173, 102, 188, 141, 142, 37, 175, 52, 198, 242, 148, 122, 8, 59, 106, 210, 83, 58,
                186, 73, 222, 91, 249, 145, 233, 92, 210, 227, 179, 119, 32, 93
            ]
        );
    }

    {
        let obj = TestEnum::<u64>::Option2(123);

        let expected_ast = ASTNode::from(ASTVariant {
            context: b"var2",
            name: b"TestEnum".to_vec(),
            which: 1,
            value: Some(Box::new(ASTNode::from(ASTPrimitive {
                context: b"Option2",
                type_name: b"uint",
                data: 123u64.to_le_bytes().to_vec(),
            }))),
        });

        digestible_test_case_ast("var2", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var2"),
            [
                66, 147, 63, 233, 146, 77, 54, 143, 27, 179, 144, 29, 136, 35, 162, 184, 165, 169,
                240, 67, 44, 53, 254, 235, 140, 181, 216, 118, 61, 189, 60, 217
            ]
        );
    }

    {
        let s: &str = "a string";
        let obj = TestEnum::<u64>::Option3(1234, s.to_owned());

        let expected_ast = ASTNode::from(ASTVariant {
            context: b"var3",
            name: b"TestEnum".to_vec(),
            which: 2,
            value: Some(Box::new(ASTNode::from(ASTAggregate {
                context: b"Option3",
                name: Default::default(),
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"0",
                        type_name: b"uint",
                        data: 1234u32.to_le_bytes().to_vec(),
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"1",
                        type_name: b"str",
                        data: s.as_bytes().to_vec(),
                    }),
                ],
                is_completed: true,
            }))),
        });

        digestible_test_case_ast("var3", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var3"),
            [
                65, 241, 44, 95, 204, 224, 62, 164, 111, 143, 140, 215, 185, 242, 13, 214, 93, 76,
                153, 214, 135, 194, 26, 173, 168, 244, 114, 107, 200, 16, 109, 123
            ]
        );
    }

    {
        let obj = TestEnum::<u64>::Option4 { a: 123, b: 456 };

        let expected_ast = ASTNode::Variant(ASTVariant {
            context: b"var4",
            name: b"TestEnum".to_vec(),
            which: 3,
            value: Some(Box::new(ASTNode::from(ASTAggregate {
                context: b"Option4",
                name: Default::default(),
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"a",
                        type_name: b"uint",
                        data: 123u64.to_le_bytes().to_vec(),
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"b",
                        type_name: b"uint",
                        data: 456u64.to_le_bytes().to_vec(),
                    }),
                ],
                is_completed: true,
            }))),
        });

        digestible_test_case_ast("var4", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var4"),
            [
                207, 173, 80, 56, 190, 91, 104, 142, 115, 86, 0, 73, 148, 160, 133, 68, 173, 159,
                163, 152, 198, 177, 12, 247, 12, 116, 161, 239, 211, 12, 28, 171
            ]
        );
    }
}

// An evolution of TestEnum<u64>
#[allow(dead_code)]
#[derive(Digestible)]
#[digestible(name = "TestEnum")]
enum TestEnumV2 {
    Option1(Option<String>),
    Option2(u64),
    Option3(u32, String),
    Option4 { a: u64, b: u64 },
}

// An evolution of TestEnumV2
#[allow(dead_code)]
#[derive(Digestible)]
#[digestible(name = "TestEnum")]
enum TestEnumV3 {
    Option1(Option<String>),
    Option2(u64),
    Option3(u32, String),
    Option4 { a: u64, b: u64, c: Option<String> },
}

// An evolution of TestEnum<u64>
#[allow(dead_code)]
#[derive(Digestible)]
#[digestible(name = "TestEnum")]
enum TestEnumV4 {
    Option1(Vec<String>),
    Option2(u64),
    Option3(u32, String),
    Option4 { a: u64, b: u64 },
}

#[test]
fn test_enum_options() {
    {
        let obj = TestEnumV2::Option1(None);

        let expected_ast = ASTNode::Variant(ASTVariant {
            context: b"var1",
            name: b"TestEnum".to_vec(),
            which: 0,
            value: Some(Box::new(ASTNode::from(ASTNone {
                context: b"Option1",
            }))),
        });

        digestible_test_case_ast("var1", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var1"),
            [
                173, 102, 188, 141, 142, 37, 175, 52, 198, 242, 148, 122, 8, 59, 106, 210, 83, 58,
                186, 73, 222, 91, 249, 145, 233, 92, 210, 227, 179, 119, 32, 93
            ]
        );
    }

    {
        let obj = TestEnumV2::Option1(Some("asdf".into()));

        let expected_ast = ASTNode::from(ASTVariant {
            context: b"var1",
            name: b"TestEnum".to_vec(),
            which: 0,
            value: Some(Box::new(ASTNode::from(ASTPrimitive {
                context: b"Option1",
                type_name: b"str",
                data: b"asdf".to_vec(),
            }))),
        });

        digestible_test_case_ast("var1", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var1"),
            [
                186, 151, 131, 141, 165, 24, 180, 231, 248, 0, 1, 231, 140, 204, 204, 162, 14, 247,
                70, 229, 224, 89, 78, 245, 62, 249, 47, 236, 41, 59, 106, 105
            ]
        );
    }

    {
        let obj = TestEnumV4::Option1(vec!["asdf".into()]);

        let expected_ast = ASTNode::from(ASTVariant {
            context: b"var1",
            name: b"TestEnum".to_vec(),
            which: 0,
            value: Some(Box::new(ASTNode::from(ASTSequence {
                context: b"Option1",
                len: 1,
                elems: vec![ASTNode::from(ASTPrimitive {
                    context: b"",
                    type_name: b"str",
                    data: b"asdf".to_vec(),
                })],
            }))),
        });

        digestible_test_case_ast("var1", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var1"),
            [
                233, 62, 47, 168, 97, 170, 22, 188, 19, 251, 7, 72, 204, 53, 167, 117, 222, 236,
                53, 73, 216, 229, 212, 27, 19, 241, 208, 67, 217, 66, 175, 172
            ]
        );
    }

    {
        let obj = TestEnumV2::Option3(19, "foobar".to_string());

        let expected_ast = ASTNode::Variant(ASTVariant {
            context: b"var1",
            name: b"TestEnum".to_vec(),
            which: 2,
            value: Some(Box::new(ASTNode::from(ASTAggregate {
                context: b"Option3",
                name: b"".to_vec(),
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"0",
                        type_name: b"uint",
                        data: 19u32.to_le_bytes().to_vec(),
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"1",
                        type_name: b"str",
                        data: b"foobar".to_vec(),
                    }),
                ],
                is_completed: true,
            }))),
        });

        digestible_test_case_ast("var1", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var1"),
            [
                199, 225, 19, 74, 203, 192, 203, 68, 209, 219, 146, 57, 104, 174, 10, 196, 50, 171,
                58, 165, 198, 196, 106, 39, 157, 251, 205, 172, 189, 110, 82, 46
            ]
        );
    }

    {
        let obj = TestEnumV2::Option4 { a: 19, b: 28 };

        let expected_ast = ASTNode::Variant(ASTVariant {
            context: b"var1",
            name: b"TestEnum".to_vec(),
            which: 3,
            value: Some(Box::new(ASTNode::from(ASTAggregate {
                context: b"Option4",
                name: b"".to_vec(),
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"a",
                        type_name: b"uint",
                        data: 19u64.to_le_bytes().to_vec(),
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"b",
                        type_name: b"uint",
                        data: 28u64.to_le_bytes().to_vec(),
                    }),
                ],
                is_completed: true,
            }))),
        });

        digestible_test_case_ast("var1", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var1"),
            [
                6, 230, 93, 2, 120, 116, 185, 206, 127, 109, 201, 79, 223, 194, 13, 32, 18, 224,
                194, 155, 72, 122, 173, 211, 126, 201, 97, 55, 194, 185, 131, 14
            ]
        );
    }

    {
        let obj = TestEnumV3::Option4 {
            a: 19,
            b: 28,
            c: None,
        };

        let expected_ast = ASTNode::Variant(ASTVariant {
            context: b"var1",
            name: b"TestEnum".to_vec(),
            which: 3,
            value: Some(Box::new(ASTNode::from(ASTAggregate {
                context: b"Option4",
                name: b"".to_vec(),
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"a",
                        type_name: b"uint",
                        data: 19u64.to_le_bytes().to_vec(),
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"b",
                        type_name: b"uint",
                        data: 28u64.to_le_bytes().to_vec(),
                    }),
                ],
                is_completed: true,
            }))),
        });

        digestible_test_case_ast("var1", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var1"),
            [
                6, 230, 93, 2, 120, 116, 185, 206, 127, 109, 201, 79, 223, 194, 13, 32, 18, 224,
                194, 155, 72, 122, 173, 211, 126, 201, 97, 55, 194, 185, 131, 14
            ]
        );
    }

    {
        let obj = TestEnumV3::Option4 {
            a: 19,
            b: 28,
            c: Some("foobar".into()),
        };

        let expected_ast = ASTNode::Variant(ASTVariant {
            context: b"var1",
            name: b"TestEnum".to_vec(),
            which: 3,
            value: Some(Box::new(ASTNode::from(ASTAggregate {
                context: b"Option4",
                name: b"".to_vec(),
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"a",
                        type_name: b"uint",
                        data: 19u64.to_le_bytes().to_vec(),
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"b",
                        type_name: b"uint",
                        data: 28u64.to_le_bytes().to_vec(),
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"c",
                        type_name: b"str",
                        data: b"foobar".to_vec(),
                    }),
                ],
                is_completed: true,
            }))),
        });

        digestible_test_case_ast("var1", &obj, expected_ast);
        assert_eq!(
            obj.digest32::<MerlinTranscript>(b"var1"),
            [
                71, 173, 71, 143, 202, 135, 44, 56, 80, 234, 96, 200, 51, 227, 12, 71, 41, 73, 46,
                188, 145, 34, 229, 155, 28, 212, 81, 2, 142, 125, 64, 88
            ]
        );
    }
}

// Test enum schema evolution properties
#[test]
fn test_enum_schema_evolution() {
    assert_eq!(
        calculate_digest_ast(b"test", &TestEnum::<u64>::Option1),
        calculate_digest_ast(b"test", &TestEnumV2::Option1(None))
    );

    assert_eq!(
        calculate_digest_ast(b"test", &TestEnum::<u64>::Option1),
        calculate_digest_ast(b"test", &TestEnumV4::Option1(Default::default()))
    );

    assert_ne!(
        calculate_digest_ast(b"test", &TestEnumV2::Option1(Some("foobar".into()))),
        calculate_digest_ast(b"test", &TestEnumV4::Option1(vec!["foobar".into()]))
    );

    assert_eq!(
        calculate_digest_ast(b"test", &TestEnum::<u64>::Option4 { a: 1, b: 2 }),
        calculate_digest_ast(
            b"test",
            &TestEnumV3::Option4 {
                a: 1,
                b: 2,
                c: None
            }
        )
    );
}
