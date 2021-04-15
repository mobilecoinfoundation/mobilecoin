//! Test that our AST nodes are mapping to the append bytes calls that we
//! expect. This is basically a test that the default implementations of
//! `append_primitive` etc. in the DigestTranscript crate match the spec, and
//! that nothing else went wrong wiring all this stuff up.
use mc_crypto_digestible::DigestTranscript;
use mc_crypto_digestible_test_utils::{
    ASTAggregate, ASTNode, ASTNone, ASTPrimitive, ASTSequence, ASTVariant, MockMerlin,
};

fn ast_test_case(obj: &ASTNode, expected_append_bytes: &[(Vec<u8>, Vec<u8>)]) {
    let mut transcript = MockMerlin::new();
    obj.append_to_transcript(&mut transcript);
    if &transcript.append_bytes_calls[..] != expected_append_bytes {
        panic!(
            "AST test case failed:\nExpected:\n{:?}\nFound:\n{:?}",
            expected_append_bytes, transcript.append_bytes_calls
        );
    }
}

// Test that ASTPrimitive examples correspond to expected append_bytes calls
#[test]
fn digest_primitive_append_bytes() {
    let prim1 = ASTNode::from(ASTPrimitive {
        context: b"foo",
        type_name: b"bar",
        data: b"baz".to_vec(),
    });
    ast_test_case(
        &prim1,
        &[
            (b"foo".to_vec(), b"prim".to_vec()),
            (b"bar".to_vec(), b"baz".to_vec()),
        ],
    );

    let prim2 = ASTNode::from(ASTPrimitive {
        context: b"fiz",
        type_name: b"buz",
        data: b"".to_vec(),
    });
    ast_test_case(
        &prim2,
        &[
            (b"fiz".to_vec(), b"prim".to_vec()),
            (b"buz".to_vec(), b"".to_vec()),
        ],
    );
}

// Test that ASTSequence examples correspond to expected append_bytes calls
#[test]
fn digest_sequence_append_bytes() {
    let prim1 = ASTNode::from(ASTPrimitive {
        context: b"foo",
        type_name: b"bar",
        data: b"baz".to_vec(),
    });
    let prim2 = ASTNode::from(ASTPrimitive {
        context: b"fiz",
        type_name: b"buz",
        data: b"".to_vec(),
    });

    let seq1 = ASTNode::from(ASTSequence {
        context: b"list",
        len: 1,
        elems: vec![prim2.clone()],
    });

    ast_test_case(
        &seq1,
        &[
            (b"list".to_vec(), b"seq".to_vec()),
            (b"len".to_vec(), 1u64.to_le_bytes().to_vec()),
            (b"fiz".to_vec(), b"prim".to_vec()),
            (b"buz".to_vec(), b"".to_vec()),
        ],
    );

    let seq2 = ASTNode::from(ASTSequence {
        context: b"list2",
        len: 1,
        elems: vec![prim1.clone()],
    });

    ast_test_case(
        &seq2,
        &[
            (b"list2".to_vec(), b"seq".to_vec()),
            (b"len".to_vec(), 1u64.to_le_bytes().to_vec()),
            (b"foo".to_vec(), b"prim".to_vec()),
            (b"bar".to_vec(), b"baz".to_vec()),
        ],
    );

    let seq3 = ASTNode::from(ASTSequence {
        context: b"list3",
        len: 2,
        elems: vec![prim1, prim2],
    });

    ast_test_case(
        &seq3,
        &[
            (b"list3".to_vec(), b"seq".to_vec()),
            (b"len".to_vec(), 2u64.to_le_bytes().to_vec()),
            (b"foo".to_vec(), b"prim".to_vec()),
            (b"bar".to_vec(), b"baz".to_vec()),
            (b"fiz".to_vec(), b"prim".to_vec()),
            (b"buz".to_vec(), b"".to_vec()),
        ],
    );
}

// Test that ASTAggregate examples correspond to expected append_bytes calls
#[test]
fn digest_aggregate_append_bytes() {
    let prim1 = ASTNode::from(ASTPrimitive {
        context: b"foo",
        type_name: b"bar",
        data: b"baz".to_vec(),
    });
    let prim2 = ASTNode::from(ASTPrimitive {
        context: b"fiz",
        type_name: b"buz",
        data: b"".to_vec(),
    });

    let agg1 = ASTNode::from(ASTAggregate {
        context: b"stuff",
        name: b"blob".to_vec(),
        elems: Default::default(),
        is_completed: true,
    });

    ast_test_case(
        &agg1,
        &[
            (b"stuff".to_vec(), b"agg".to_vec()),
            (b"name".to_vec(), b"blob".to_vec()),
            (b"stuff".to_vec(), b"agg-end".to_vec()),
            (b"name".to_vec(), b"blob".to_vec()),
        ],
    );

    let seq2 = ASTNode::from(ASTAggregate {
        context: b"stuff2",
        name: b"blob".to_vec(),
        elems: vec![prim1.clone()],
        is_completed: true,
    });

    ast_test_case(
        &seq2,
        &[
            (b"stuff2".to_vec(), b"agg".to_vec()),
            (b"name".to_vec(), b"blob".to_vec()),
            (b"foo".to_vec(), b"prim".to_vec()),
            (b"bar".to_vec(), b"baz".to_vec()),
            (b"stuff2".to_vec(), b"agg-end".to_vec()),
            (b"name".to_vec(), b"blob".to_vec()),
        ],
    );

    let seq3 = ASTNode::from(ASTAggregate {
        context: b"stuff3",
        name: b"blob".to_vec(),
        elems: vec![prim1.clone(), prim2.clone()],
        is_completed: true,
    });

    ast_test_case(
        &seq3,
        &[
            (b"stuff3".to_vec(), b"agg".to_vec()),
            (b"name".to_vec(), b"blob".to_vec()),
            (b"foo".to_vec(), b"prim".to_vec()),
            (b"bar".to_vec(), b"baz".to_vec()),
            (b"fiz".to_vec(), b"prim".to_vec()),
            (b"buz".to_vec(), b"".to_vec()),
            (b"stuff3".to_vec(), b"agg-end".to_vec()),
            (b"name".to_vec(), b"blob".to_vec()),
        ],
    );
}

// Test that ASTVariant examples correspond to expected append_bytes calls
#[test]
fn digest_variant_append_bytes() {
    let prim1 = ASTNode::from(ASTPrimitive {
        context: b"foo",
        type_name: b"bar",
        data: b"baz".to_vec(),
    });
    let prim2 = ASTNode::from(ASTPrimitive {
        context: b"fiz",
        type_name: b"buz",
        data: b"".to_vec(),
    });

    let var1 = ASTNode::from(ASTVariant {
        context: b"enum",
        name: b"enum_type".to_vec(),
        which: 0,
        value: Some(Box::new(prim1)),
    });

    ast_test_case(
        &var1,
        &[
            (b"enum".to_vec(), b"var".to_vec()),
            (b"name".to_vec(), b"enum_type".to_vec()),
            (b"which".to_vec(), 0u32.to_le_bytes().to_vec()),
            (b"foo".to_vec(), b"prim".to_vec()),
            (b"bar".to_vec(), b"baz".to_vec()),
        ],
    );

    let var2 = ASTNode::from(ASTVariant {
        context: b"enum",
        name: b"enum_type".to_vec(),
        which: 1,
        value: Some(Box::new(prim2)),
    });

    ast_test_case(
        &var2,
        &[
            (b"enum".to_vec(), b"var".to_vec()),
            (b"name".to_vec(), b"enum_type".to_vec()),
            (b"which".to_vec(), 1u32.to_le_bytes().to_vec()),
            (b"fiz".to_vec(), b"prim".to_vec()),
            (b"buz".to_vec(), b"".to_vec()),
        ],
    );

    let var3 = ASTNode::from(ASTVariant {
        context: b"enum",
        name: b"enum_type".to_vec(),
        which: 1,
        value: Some(Box::new(ASTNode::None(ASTNone { context: b"blar" }))),
    });

    ast_test_case(
        &var3,
        &[
            (b"enum".to_vec(), b"var".to_vec()),
            (b"name".to_vec(), b"enum_type".to_vec()),
            (b"which".to_vec(), 1u32.to_le_bytes().to_vec()),
            (b"blar".to_vec(), b"".to_vec()),
        ],
    );
}
