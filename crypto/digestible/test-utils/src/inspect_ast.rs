use core::fmt;
use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
use serde_json::json;
use std::{ops::Deref, vec::Vec};

// Digestible AST node types

/// Represents a node in the AST
///
/// Here "AST" means "abstract syntax tree", corresponding to the structure
/// that we inferred from the way that DigestTranscript protocol was exercised.
///
/// There is an enumerator here for every call to `DigestTranscript` that a
/// `Digestible` implementation is permitted to use.
///
/// An ASTNode represents a kind of "parse tree", because when InspectAST
/// captures a call, it tries to match it to its parent, and fails if it cannot,
/// in order to validate what the proc-macro is doing.
/// Therefore, its possible that the AST is in an "incomplete state", e.g. when
/// we have started, but not finished, digesting a complex value through
/// InspectAST.
///
/// To recap:
/// - A Primitive is a "simple" type (as opposed to a compound type), which has
///   a direct representation as canonical bytes.
/// - A Sequence is a variable length sequence of values of some other type. A
///   Sequence has a length known at runtime.
/// - An Aggregate is a fixed-length sequence of values ("fields"), of different
///   types. Each field has a name.
/// - A variant is a single value which may be one of several different types.
///   Each possibility has an associated name, in the context of this variant.
///   In the sequel we call this the "variant possibility name".
/// - The None value is a sentinel used sometimes to indicate the absence of a
///   value, inside of sequences or variants. Inside of aggregates, it is
///   permitted to omit entirely a value that is absent, to facilitate schema
///   evolution. Inside of sequences and variants, it is not, and could lead to
///   problems. None is used instead.
#[derive(Clone, Eq, PartialEq)]
pub enum ASTNode {
    /// This node represents a call to append_primitive
    Primitive(ASTPrimitive),
    /// This node represents a call to append_none
    None(ASTNone),
    /// This node represents a call to append_seq_header, and any subsequent
    /// children that we have captured, which are stored in its "elems"
    /// field.
    Sequence(ASTSequence),
    /// This node represents a call to append_agg_header, and any subsequent
    /// children that we have captured, which are stored in its "elems"
    /// field.
    Aggregate(ASTAggregate),
    /// This node represents a call to append_agg_header, and the subsequent
    /// child that we may have captured, which is stored in its "value"
    /// field.
    Variant(ASTVariant),
}

/// Represents a call to DigestTranscript.append_primitive
/// Meant to be used with types that are "simple"
/// and have a natural canonical representation as bytes
#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct ASTPrimitive {
    /// The context argument to `append_primitive`
    pub context: &'static [u8],
    /// The type_name argument to `append_primitive`
    pub type_name: &'static [u8],
    /// The data argument to `append_primitive`
    pub data: Vec<u8>,
}

/// Represents a call to DigestTranscript.append_none
/// This is used in some rare cases -- for Option value which is None,
/// and for a rust enum value which has no associated value.
/// When those values are fields in an agg, they can be omitted completely.
/// When they are children of seq or var, they cannot be omitted, and None must
/// be appended instead.
#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct ASTNone {
    /// The context argument to `append_none`
    pub context: &'static [u8],
}

/// Represents a call to DigestTranscript.append_seq_header,
/// and the subsequent child nodes that must be pushed.
#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct ASTSequence {
    /// The context argument to `append_seq_header`
    pub context: &'static [u8],
    /// The len argument to `append_seq_header`
    pub len: u64,
    /// The subsequent calls corresponding to children of the seq node
    pub elems: Vec<ASTNode>,
}

/// Represents a call to DigestTranscript.append_agg_header,
/// and the subsequent child nodes that may be pushed,
/// and the closing call to DigestTrancript.append_agg_closer,
#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct ASTAggregate {
    /// The context argument to `append_agg_header`
    pub context: &'static [u8],
    /// The name argument to `append_agg_header`
    pub name: Vec<u8>,
    /// The subsequent calls corresponding to children appended to the agg node
    pub elems: Vec<ASTNode>,
    /// A flag indicating if we saw a matching `append_agg_closer` yet
    pub is_completed: bool,
}

/// Represents a call to DigestTranscript.append_var_header,
/// and the subsequent call to append a child node.
#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct ASTVariant {
    /// The context argument to `append_var_header`
    pub context: &'static [u8],
    /// The name argument to `append_var_header`
    pub name: Vec<u8>,
    /// The which argument to `append_var_header`
    pub which: u32,
    /// The subsequent child, if encountered yet, of this variant node.
    /// This option value is None if we did not yet encounter it.
    ///
    /// Box is required here to break the following cycle:
    /// ASTNode is a rust enum containing ASTVariant as a possible value,
    /// so sizeof(ASTNode>) > sizeof(ASTVariant).
    /// But if Box is not used, then ASTVariant contains Option<ASTNode> as a
    /// member, so sizeof(ASTVariant) > sizeof(ASTNode).
    /// In otherwords the size of ASTNode on the stack could not be fixed at
    /// compile-time. Using Box permits to break this cycle, so that
    /// ASTVariant has a small size on the stack independent of the size of
    /// ASTNode.
    pub value: Option<Box<ASTNode>>,
}

impl ASTNode {
    /// Helper for parsing: Find the deepest "incomplete child" in the tree
    /// where we should attempt to add the next appended piece of data, if we
    /// want to be able to reconstruct the full AST
    //
    // The &mut self version of this function appears to be impossible to write
    // in stable rust without breaking borrow-checker rules.
    // When Self is an enum and we match on self, the borrow checker does not allow
    // there to be a code path returning &mut Self if there is any match arm that
    // returns a result that requires &mut self lifetime, it says that the scope
    // for which self is potentially grabbed by this return is the entire function
    // rather than, the portion of the function leading up to the possible return.
    // I think this is a defect, and I couldn't find any work-around.
    //
    // To avoid this, and avoid code duplication, we implement the logic for &self,
    // and implement the &mut self version using the equivalent of a const-cast.
    // This is pretty ugly, but it should work, and fortunately it appears to work.
    // This is only test code that doesn't get shipped.
    #[inline(never)]
    #[allow(clippy::transmute_ptr_to_ptr)]
    pub fn find_incomplete_child_mut(&mut self) -> Option<&mut ASTNode> {
        self.find_incomplete_child().map(|x| {
            // Safety:
            // At the time that this function is called, &mut self is the only
            // possible reference to self in the entire program, per semantics of &mut being
            // an exclusive reference.
            //
            // Necessarily, this excludes the existence of any reference elsewhere in the
            // program to self or any of its children.
            //
            // When we call find_incomplete_child(), this call returns either &self,
            // or a child of self.
            //
            // At the time that we then cast that reference back to &mut (unsafely),
            // and then return it to caller,
            // it is necessarily the case that there is no other reference in the program
            // to that value. So we have upheld the semantics of `&mut`.
            //
            // inline(never) is used to try to discourage the compiler from peering into
            // here and thinking too hard about it, since nomicon says this is
            // undefined behavior.
            let ptr: *mut ASTNode = unsafe { core::mem::transmute(x as *const ASTNode) };
            unsafe { &mut *ptr }
        })
    }

    /// Implementation details of find incomplete child
    fn find_incomplete_child(&self) -> Option<&ASTNode> {
        match self {
            // Primitives don't have any children
            Self::Primitive(_) => None,
            // None doesn't have any children
            Self::None(_) => None,
            // Otherwise, if our number of elements is equal to our promised length,
            // then we are not incompletey
            Self::Sequence(seq) => {
                let elems_len = seq.elems.len() as u64;
                if let Some(child) = seq
                    .elems
                    .last()
                    .and_then(|back| back.find_incomplete_child())
                {
                    // If the most recent child of the sequence node has
                    // an incomplete child, then return that child (since it is deeper than us).
                    Some(child)
                } else if seq.len == elems_len {
                    // Otherwise, if our number of elements is equal to our promised length,
                    // then we are complete, so return None.
                    None
                } else {
                    // Otherwise, we have less elements than promised, and should return ourself.
                    // If we have more elements than promised, this is a bug in this file.
                    assert!(
                        seq.len > elems_len,
                        "more than expected number of sequence elements"
                    );
                    Some(self)
                }
            }
            Self::Aggregate(agg) => {
                if let Some(child) = agg
                    .elems
                    .last()
                    .and_then(|back| back.find_incomplete_child())
                {
                    // If the most recent child of the aggregate node has
                    // an incomplete child, then return that child (since it is deeper than us).
                    Some(child)
                } else if agg.is_completed {
                    // Otherwise, if we have been closed,
                    // then we are complete, so return None.
                    None
                } else {
                    // Otherwise, return ourself, since we have not been completed.
                    Some(self)
                }
            }
            Self::Variant(var) => {
                if let Some(val) = var.value.as_ref() {
                    // If the variant already has a child (which might be a compound child),
                    // then call find_incomplete_child recursively on the child.
                    val.find_incomplete_child()
                } else {
                    // Otherwise, we don't have a child yet, so we are incomplete.
                    Some(self)
                }
            }
        }
    }
}

/// This is a debugging aid which implements DigestTranscript protocol, but
/// captures the AST instead of reudcing everything to append_bytes calls.
#[derive(Default, Clone, Debug)]
pub struct InspectAST {
    pub ast_nodes: Vec<ASTNode>,
}

impl InspectAST {
    // Given an ASTNode (corresponding to the most recent call to a function from
    // DigestTranscript), find its parent in the tree, or make it the next
    // root-level element in self.ast_nodes.
    fn push_ast_node(&mut self, new_node: ASTNode) {
        if let Some(incomplete_node) = self
            .ast_nodes
            .last_mut()
            .and_then(|x| x.find_incomplete_child_mut())
        {
            // The result of find_incomplete_child_mut should be parent of the new node
            match incomplete_node {
                ASTNode::Primitive(_) => panic!("Can't append children to primitive"),
                ASTNode::None(_) => panic!("Can't append children to none"),
                ASTNode::Sequence(seq) => {
                    assert!(
                        (seq.elems.len() as u64) < seq.len,
                        "Can't append unexpected values to sequence"
                    );
                    seq.elems.push(new_node);
                }
                ASTNode::Aggregate(agg) => {
                    assert!(
                        !agg.is_completed,
                        "Can't append to aggregate that is already marked completed"
                    );
                    agg.elems.push(new_node);
                }
                ASTNode::Variant(var) => {
                    assert!(
                        var.value.is_none(),
                        "Can't add value to a variant that already has a value: {}",
                        var.value.as_ref().unwrap()
                    );
                    var.value = Some(Box::new(new_node));
                }
            }
        } else {
            // Either there are no root-level elements, or the most recent one is already
            // complete.
            self.ast_nodes.push(new_node);
        }
    }
}

// Implement DigestTranscript for InspectAst by creating a new ASTNode
// corresponding to the call, and calling self.push_ast_node to insert it into
// the structure at the appropriate point.
impl DigestTranscript for InspectAST {
    fn new() -> Self {
        Default::default()
    }
    fn append_bytes(&mut self, _context: &'static [u8], _data: impl AsRef<[u8]>) {
        panic!("This should not be called directly by implementations of Digestible trait")
    }
    fn extract_digest(self, _ouptut: &mut [u8; 32]) {
        panic!("The AST inspector is not able to actually create digests")
    }

    fn append_primitive(
        &mut self,
        context: &'static [u8],
        type_name: &'static [u8],
        data: impl AsRef<[u8]>,
    ) {
        self.push_ast_node(ASTNode::Primitive(ASTPrimitive {
            context,
            type_name,
            data: data.as_ref().to_vec(),
        }));
    }
    fn append_none(&mut self, context: &'static [u8]) {
        self.push_ast_node(ASTNode::None(ASTNone { context }));
    }
    fn append_seq_header(&mut self, context: &'static [u8], len: usize) {
        self.push_ast_node(ASTNode::Sequence(ASTSequence {
            context,
            len: len as u64,
            elems: Default::default(),
        }));
    }
    fn append_agg_header(&mut self, context: &'static [u8], name: &[u8]) {
        self.push_ast_node(ASTNode::Aggregate(ASTAggregate {
            context,
            name: name.to_vec(),
            elems: Default::default(),
            is_completed: false,
        }));
    }
    fn append_agg_closer(&mut self, context: &'static [u8], name: &[u8]) {
        let incomplete_node = self
            .ast_nodes
            .last_mut()
            .expect("No ast nodes found to close")
            .find_incomplete_child_mut()
            .expect("No incomplete child found to close");
        match incomplete_node {
            ASTNode::Aggregate(agg) => {
                assert!(
                    !agg.is_completed,
                    "This aggregate was already marked completed"
                );
                assert!(
                    agg.context == context,
                    "Tried to close aggregate but wrong context was found"
                );
                assert!(
                    &agg.name[..] == name,
                    "Tried to close aggregate but wrong name was found"
                );
                agg.is_completed = true;
            }
            _ => panic!("Unexpected agg_closer"),
        }
    }
    fn append_var_header(&mut self, context: &'static [u8], type_name: &[u8], which: u32) {
        self.push_ast_node(ASTNode::Variant(ASTVariant {
            context,
            name: type_name.to_vec(),
            which,
            value: None,
        }));
    }
}

// Make an "append to transcript" function for ASTNode
// This allows to create tests that the AST "explains the hash"
// by making a digestible structure, getting its merlin digest, and its AST,
// then computing the merlin digest from the AST, and checking that it matches.
//
// We don't simply implement Digestible for ASTNode, because ASTNode's carry
// their context, but Digestible API requires to provide a context.
impl ASTNode {
    pub fn append_to_transcript<DT: DigestTranscript>(&self, transcript: &mut DT) {
        match self {
            ASTNode::Primitive(prim) => {
                transcript.append_primitive(prim.context, prim.type_name.as_ref(), &prim.data[..])
            }
            ASTNode::None(none) => transcript.append_none(none.context.as_ref()),
            ASTNode::Sequence(seq) => {
                assert!(seq.elems.len() as u64 == seq.len, "incomplete seq node");
                transcript.append_seq_header(seq.context, seq.len as usize);
                for elem in seq.elems.iter() {
                    elem.append_to_transcript(transcript);
                }
            }
            ASTNode::Aggregate(agg) => {
                assert!(agg.is_completed, "incomplete agg node");
                transcript.append_agg_header(agg.context, agg.name.as_ref());
                for elem in agg.elems.iter() {
                    elem.append_to_transcript(transcript);
                }
                transcript.append_agg_closer(agg.context, agg.name.as_ref());
            }
            ASTNode::Variant(var) => {
                transcript.append_var_header(var.context, var.name.as_ref(), var.which);
                var.value
                    .as_ref()
                    .expect("incomplete var node")
                    .append_to_transcript(transcript);
            }
        }
    }
}

/// Given a digestible object, visit it with the InspectAST visitor to produce
/// an AST node. Assert that this works.
/// Also, compute the merlin digest directly, and via the AST,
/// and check that they match.
pub fn calculate_digest_ast<O: Digestible>(context: &'static [u8], obj: &O) -> ASTNode {
    let merlin_digest = obj.digest32::<MerlinTranscript>(context);

    let ast = {
        let mut inspector = InspectAST::default();
        obj.append_to_transcript(context, &mut inspector);

        assert_eq!(
            inspector.ast_nodes.len(),
            1,
            "Did not produce a single well-formed AST node"
        );
        assert!(
            inspector.ast_nodes[0].find_incomplete_child().is_none(),
            "AST node was incomplete"
        );
        inspector.ast_nodes[0].clone()
    };

    let ast_merlin_digest = {
        let mut transcript = <MerlinTranscript as DigestTranscript>::new();
        ast.append_to_transcript(&mut transcript);
        let mut result = [0u8; 32];
        transcript.extract_digest(&mut result);
        result
    };

    assert!(
        merlin_digest == ast_merlin_digest,
        "AST merlin digest did not match merlin digest, the AST does not explain the hash"
    );

    ast
}

// From implementations
impl From<ASTPrimitive> for ASTNode {
    fn from(src: ASTPrimitive) -> Self {
        Self::Primitive(src)
    }
}

impl From<ASTNone> for ASTNode {
    fn from(src: ASTNone) -> Self {
        Self::None(src)
    }
}

impl From<ASTSequence> for ASTNode {
    fn from(src: ASTSequence) -> Self {
        Self::Sequence(src)
    }
}

impl From<ASTAggregate> for ASTNode {
    fn from(src: ASTAggregate) -> Self {
        Self::Aggregate(src)
    }
}

impl From<ASTVariant> for ASTNode {
    fn from(src: ASTVariant) -> Self {
        Self::Variant(src)
    }
}

// Display and debug implementations

// Implement core::fmt::Debug for ASTNode in a less verbose way
impl fmt::Debug for ASTNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ASTNode::Primitive(prim) => <ASTPrimitive as fmt::Debug>::fmt(prim, f),
            ASTNode::None(none) => <ASTNone as fmt::Debug>::fmt(none, f),
            ASTNode::Sequence(seq) => <ASTSequence as fmt::Debug>::fmt(seq, f),
            ASTNode::Aggregate(agg) => <ASTAggregate as fmt::Debug>::fmt(agg, f),
            ASTNode::Variant(var) => <ASTVariant as fmt::Debug>::fmt(var, f),
        }
    }
}

// Implement serde_json::Value from each of the AST types,
// and implement Display using serde_json::pretty_print
//
// These json conversions are not meant to be anything except a convenient way
// to get pretty printing without having to roll my own

impl From<&ASTNode> for serde_json::Value {
    fn from(src: &ASTNode) -> Self {
        match src {
            ASTNode::Primitive(src) => Self::from(src),
            ASTNode::None(src) => Self::from(src),
            ASTNode::Sequence(src) => Self::from(src),
            ASTNode::Aggregate(src) => Self::from(src),
            ASTNode::Variant(src) => Self::from(src),
        }
    }
}

impl From<&ASTPrimitive> for serde_json::Value {
    fn from(src: &ASTPrimitive) -> Self {
        json!({
            utf8(&src.context): "primitive",
            "type_name": utf8(&src.type_name),
            "data": pretty_bytes(&src.data)
        })
    }
}

impl From<&ASTNone> for serde_json::Value {
    fn from(src: &ASTNone) -> Self {
        json!({
            utf8(&src.context): "",
        })
    }
}

impl From<&ASTSequence> for serde_json::Value {
    fn from(src: &ASTSequence) -> Self {
        let mut result = json!({
            utf8(&src.context): "sequence",
            "len": src.len,
        });
        result.as_object_mut().unwrap().insert(
            "elems".to_string(),
            serde_json::Value::Array(src.elems.iter().map(serde_json::Value::from).collect()),
        );
        result
    }
}

impl From<&ASTAggregate> for serde_json::Value {
    fn from(src: &ASTAggregate) -> Self {
        let mut result = json!({
            utf8(&src.context): "aggregate",
            "name": utf8(&src.name),
        });
        result.as_object_mut().unwrap().insert(
            "elems".to_string(),
            serde_json::Value::Array(src.elems.iter().map(serde_json::Value::from).collect()),
        );
        result
    }
}

impl From<&ASTVariant> for serde_json::Value {
    fn from(src: &ASTVariant) -> Self {
        let value_json = if let Some(node) = src.value.as_ref() {
            serde_json::Value::from(node.deref())
        } else {
            serde_json::Value::String("**incomplete**".to_string())
        };
        json!({
            utf8(&src.context): "variant",
            "name": utf8(&src.name),
            "which": src.which,
            "value": value_json,
        })
    }
}

impl fmt::Display for ASTNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let obj = serde_json::Value::from(self);
        write!(f, "{}", serde_json::to_string_pretty(&obj).unwrap())
    }
}

impl fmt::Display for ASTPrimitive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let obj = serde_json::Value::from(self);
        write!(f, "{}", serde_json::to_string_pretty(&obj).unwrap())
    }
}

impl fmt::Display for ASTNone {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let obj = serde_json::Value::from(self);
        write!(f, "{}", serde_json::to_string_pretty(&obj).unwrap())
    }
}

impl fmt::Display for ASTSequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let obj = serde_json::Value::from(self);
        write!(f, "{}", serde_json::to_string_pretty(&obj).unwrap())
    }
}

impl fmt::Display for ASTAggregate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let obj = serde_json::Value::from(self);
        write!(f, "{}", serde_json::to_string_pretty(&obj).unwrap())
    }
}

impl fmt::Display for ASTVariant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let obj = serde_json::Value::from(self);
        write!(f, "{}", serde_json::to_string_pretty(&obj).unwrap())
    }
}

// Internal helper: Vec<u8> to owned pretty-printed bytes
// This should be easy to copy-paste into rust source code as a [u8] array
fn pretty_bytes(src: impl AsRef<[u8]>) -> String {
    format!("{:?}", src.as_ref())
}

// Internal helper: Vec<u8> to String, which is asserted to be utf8
fn utf8(src: impl AsRef<[u8]>) -> String {
    std::str::from_utf8(src.as_ref())
        .expect("argument was not utf8")
        .to_string()
}
