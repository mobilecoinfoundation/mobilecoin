// Copyright (c) 2018-2020 MobileCoin Inc.

//! Build-time wrapper around the LLVM bolt command

#![deny(missing_docs)]

use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    path::{Path, PathBuf},
    process::Command,
};

/// An enumeration of valid options when trying to fix instruction alignment for
/// macro-fusion (x86 relocation mode).
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MacroFusionAlignments {
    /// Do not insert alignment no-ops for macro-fusion.
    None,
    /// Only insert alignment no-ops on hot execution paths (default).
    Hot,
    /// Always align instructions to allow macro-fusion.
    All,
}

impl Default for MacroFusionAlignments {
    fn default() -> MacroFusionAlignments {
        MacroFusionAlignments::Hot
    }
}

impl Display for MacroFusionAlignments {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let result = match self {
            MacroFusionAlignments::None => "none",
            MacroFusionAlignments::All => "all",
            MacroFusionAlignments::Hot => "hot",
        };
        write!(f, "{}", result)
    }
}

/// A command builder for the `llvm-bolt` utility.
///
/// There are a ton of options for this utility, and (slightly more) for
/// Signal's version of it, which we use. This builder presently exposes only
/// the options MobileCoin is using, though patches to add support for other
/// options are welcome.
#[derive(Clone, Default, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LlvmBolt {
    trap_old_code: Option<bool>,
    use_gnu_stack: Option<bool>,
    update_debug_sections: Option<bool>,
    update_end: Option<bool>,
    verbosity: Option<u32>,
    skip_funcs_file: Option<PathBuf>,
    eliminate_unreachable: Option<bool>,
    strip_rep_ret: Option<bool>,
    simplify_conditional_tail_calls: Option<bool>,
    align_macro_fusion: Option<MacroFusionAlignments>,
    insert_retpolines: Option<bool>,
    insert_lfences: Option<bool>,
}

impl LlvmBolt {
    /// Insert traps in old function bodies.
    pub fn trap_old_code(&mut self, trap: bool) -> &mut Self {
        self.trap_old_code = Some(trap);
        self
    }

    /// Use GNU_STACK program header for new segment (workaround for issues with
    /// strip/objcopy).
    pub fn use_gnu_stack(&mut self, use_gnu: bool) -> &mut Self {
        self.use_gnu_stack = Some(use_gnu);
        self
    }

    /// Update DWARF debug sections of the executable.
    pub fn update_debug_sections(&mut self, update: bool) -> &mut Self {
        self.update_debug_sections = Some(update);
        self
    }

    /// Update the _end symbol to point to the end of all data sections.
    pub fn update_end(&mut self, update: bool) -> &mut Self {
        self.update_end = Some(update);
        self
    }

    /// Set verbosity level for diagnostic output.
    pub fn verbosity(&mut self, level: u32) -> &mut Self {
        self.verbosity = Some(level);
        self
    }

    /// Provide a file with list of functions to skip.
    pub fn skip_funcs_file(&mut self, path: &Path) -> &mut Self {
        self.skip_funcs_file = Some(path.to_owned());
        self
    }

    /// Eliminate unreachable code (on by default).
    pub fn eliminate_unreachable(&mut self, eliminate: bool) -> &mut Self {
        self.eliminate_unreachable = Some(eliminate);
        self
    }

    /// Strip 'repz' prefix from 'repz retq' sequence (on by default).
    pub fn strip_rep_ret(&mut self, strip: bool) -> &mut Self {
        self.strip_rep_ret = Some(strip);
        self
    }

    /// Simplify conditional tail calls by removing unnecessary jumps.
    pub fn simplify_conditional_tail_calls(&mut self, simplify: bool) -> &mut Self {
        self.simplify_conditional_tail_calls = Some(simplify);
        self
    }

    /// Set when to fix instruction alignment for macro-fusion (x86 relocation
    /// mode).
    pub fn align_macro_fusion(&mut self, align: MacroFusionAlignments) -> &mut Self {
        self.align_macro_fusion = Some(align);
        self
    }

    /// Run lfence insertion pass.
    pub fn insert_retpolines(&mut self, insert: bool) -> &mut Self {
        self.insert_retpolines = Some(insert);
        self
    }

    /// Run retpoline insertion pass.
    pub fn insert_lfences(&mut self, insert: bool) -> &mut Self {
        self.insert_lfences = Some(insert);
        self
    }

    fn build_command(&self) -> Command {
        let mut retval = Command::new("llvm-bolt");

        if let Some(value) = self.trap_old_code {
            if value {
                retval.arg("-trap-old-code");
            }
        }

        if let Some(value) = self.use_gnu_stack {
            if value {
                retval.arg("-use-gnu-stack");
            }
        }

        if let Some(value) = self.update_debug_sections {
            if value {
                retval.arg("-update-debug-sections");
            }
        }

        if let Some(value) = self.update_end {
            if value {
                retval.arg("-update-end");
            }
        }

        if let Some(value) = self.verbosity {
            retval.arg(format!("-v={}", value));
        }

        if let Some(value) = &self.skip_funcs_file {
            retval.arg(format!("-skip-funcs-file={:?}", value));
        }

        if let Some(value) = self.eliminate_unreachable {
            retval.arg(format!("-eliminate-unreachable={}", value as u8));
        }

        if let Some(value) = self.strip_rep_ret {
            retval.arg(format!("-strip-rep-ret={}", value as u8));
        }

        if let Some(value) = self.simplify_conditional_tail_calls {
            retval.arg(format!("-simplify-conditional-tail-calls={}", value as u8));
        }

        if let Some(value) = self.align_macro_fusion {
            retval.arg(format!("-align-macro-fusion={}", value));
        }

        if let Some(value) = self.insert_retpolines {
            if value {
                retval.arg("-insert-retpolines");
            }
        }

        if let Some(value) = self.insert_lfences {
            if value {
                retval.arg("-insert-lfences");
            }
        }

        retval
    }

    /// Generate a command to take a single input file and output to a
    /// different file.
    pub fn single(&self, input: &Path, output: &Path) -> Command {
        let mut retval = self.build_command();

        retval.arg(format!(
            "-o={}",
            output
                .as_os_str()
                .to_str()
                .expect("Invalid UTF-8 in output filename")
        ));
        retval.arg(
            input
                .as_os_str()
                .to_str()
                .expect("Invalid UTF-8 in input filename"),
        );

        retval
    }

    /// Generate a command which will perform
    pub fn multiple<P: AsRef<Path>>(&self, inputs: &[P]) -> Command {
        let mut retval = self.build_command();

        for input in inputs {
            retval.arg(
                input
                    .as_ref()
                    .as_os_str()
                    .to_str()
                    .expect("Invalid UTF-8 in input filename"),
            );
        }

        retval
    }
}
