// Copyright (c) 2018-2020 MobileCoin Inc.

//! A node of the consensus network.

mod node_impl;
mod node_trait;

pub use node_impl::Node;
pub use node_trait::{MockScpNode, ScpNode};
