// Copyright (c) 2018-2021 The MobileCoin Foundation

/// Tests of the schema evolution properties of derive(Digestible)
/// implementations
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_digestible_test_utils::*;

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

// Test vectors for a few instances of the Thing struct, and versions of it
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

// Tests for what happens in exotic cases, like Option<Option> and Option<Vec>
// that are less likely to happen
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

// Test vectors for digests and ASTs of the TestEnum and variations
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
