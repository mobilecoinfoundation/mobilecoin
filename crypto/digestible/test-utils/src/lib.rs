use mc_crypto_digestible::{DigestTranscript, Digestible};

mod mock_merlin;
pub use mock_merlin::MockMerlin;

mod inspect_ast;
pub use inspect_ast::*;

pub fn digestible_test_case<D: Digestible>(
    context: &'static str,
    obj: &D,
    expected_append_bytes: &[(Vec<u8>, Vec<u8>)],
) {
    let mut transcript = MockMerlin::new();
    obj.append_to_transcript(context.as_bytes(), &mut transcript);
    if &transcript.append_bytes_calls[..] != expected_append_bytes {
        panic!(
            "Digestible test case failed: context = {}\nExpected:\n{:?}\nFound:\n{:?}",
            context, expected_append_bytes, transcript.append_bytes_calls
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
            "Digestible AST test case failed: context = {}\nExpected:\n{}\nFound:\n{}",
            context, expected_ast, ast
        );
    }
}
