mod inspect_ast;
mod mock_merlin;

pub use crate::{
    inspect_ast::{
        calculate_digest_ast, ASTAggregate, ASTNode, ASTNone, ASTPrimitive, ASTSequence,
        ASTVariant, InspectAST,
    },
    mock_merlin::MockMerlin,
};

use mc_crypto_digestible::{DigestTranscript, Digestible};

pub fn digestible_test_case<D: Digestible>(
    context: &'static str,
    obj: &D,
    expected_append_bytes: &[(Vec<u8>, Vec<u8>)],
) {
    let mut transcript = MockMerlin::new();
    obj.append_to_transcript(context.as_bytes(), &mut transcript);
    if &transcript.append_bytes_calls[..] != expected_append_bytes {
        let append_bytes_calls = transcript.append_bytes_calls;
        panic!(
            "Digestible test case failed: context = {context}\nExpected:\n{expected_append_bytes:?}\nFound:\n{append_bytes_calls:?}",
        );
    }
}

pub fn digestible_test_case_ast<D: Digestible>(
    context: &'static str,
    obj: &D,
    expected_ast: ASTNode,
) {
    let ast = calculate_digest_ast(context.as_bytes(), obj);
    if ast != expected_ast {
        panic!(
            "Digestible AST test case failed: context = {context}\nExpected:\n{expected_ast}\nFound:\n{ast}",
        );
    }
}
