//!

use std::{env, path::PathBuf, process::Command};

pub struct LlvmBolt(Command);

// TODO: default should check env and then fall back to a hard-coded path in OUT_DIR.
