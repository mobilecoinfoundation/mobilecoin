// Copyright (c) 2018-2020 MobileCoin Inc.

/// Common code for printing the backtrace in the same way across the different
/// supported platforms.
use rustc_demangle::demangle;

use std::{env, io, io::Write, path, path::Path};

use super::{Frame, SymbolContext};

#[cfg(target_pointer_width = "64")]
pub const HEX_WIDTH: usize = 18;

#[cfg(target_pointer_width = "32")]
pub const HEX_WIDTH: usize = 10;

/// Prints the current backtrace.
pub fn print(w: &mut dyn Write, frames: &[Frame], ctxt: &mut dyn SymbolContext) -> io::Result<()> {
    // Use a lock to prevent mixed output in multithreading context.
    // Some platforms also requires it, like `SymFromAddr` on Windows.
    //
    // NOTE(chris): This lock was moved up one layer to where we acquire the
    // SymbolContext
    _print(w, frames, ctxt)
}

fn _print(w: &mut dyn Write, frames: &[Frame], ctxt: &mut dyn SymbolContext) -> io::Result<()> {
    let (skipped_before, skipped_after) = (0, 0);
    // NOTE(chris): Disabling filtering options for now, just taking full backtrace
    //    = filter_frames(&frames, &context);
    let format = PrintFormat::Full;
    writeln!(w, "stack backtrace:")?;

    let filtered_frames = &frames[..frames.len() - skipped_after];
    for (index, frame) in filtered_frames.iter().skip(skipped_before).enumerate() {
        ctxt.resolve_symname(&*frame, &mut |symname| {
            output(w, index, *frame, symname, format)
        })?;
        let has_more_filenames = ctxt.foreach_symbol_fileline(&*frame, &mut |file, line| {
            output_fileline(w, file, line, format)
        })?;
        if has_more_filenames {
            w.write_all(b" <... and possibly more>")?;
        }
    }

    Ok(())
}

/// Controls how the backtrace should be formatted.
///
/// Note(chris): I only implemented Full for now
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PrintFormat {
    /// Show only relevant data from the backtrace.
    Short = 2,
    /// Show all the frames with absolute path for files.
    Full = 3,
}

/// Print the symbol of the backtrace frame.
///
/// These output functions should now be used everywhere to ensure consistency.
/// You may want to also use `output_fileline`.
fn output(
    w: &mut dyn Write,
    idx: usize,
    frame: Frame,
    s: Option<&str>,
    format: PrintFormat,
) -> io::Result<()> {
    // Remove the `17: 0x0 - <unknown>` line.
    if format == PrintFormat::Short && frame.exact_position.is_null() {
        return Ok(());
    }
    match format {
        PrintFormat::Full => write!(w, "  {:2}: {:2$?} - ", idx, frame.exact_position, HEX_WIDTH)?,
        PrintFormat::Short => write!(w, "  {:2}: ", idx)?,
    }
    match s {
        Some(string) => {
            let symbol = demangle(string);
            match format {
                PrintFormat::Full => write!(w, "{}", symbol)?,
                // strip the trailing hash if short mode
                PrintFormat::Short => write!(w, "{:#}", symbol)?,
            }
        }
        None => w.write_all(b"<unknown>")?,
    }
    w.write_all(b"\n")
}

/// Print the filename and line number of the backtrace frame.
///
/// See also `output`.
#[allow(dead_code)]
fn output_fileline(
    w: &mut dyn Write,
    file: &[u8],
    line: u32,
    format: PrintFormat,
) -> io::Result<()> {
    // prior line: "  ##: {:2$} - func"
    w.write_all(b"")?;
    match format {
        PrintFormat::Full => write!(w, "           {:1$}", "", HEX_WIDTH)?,
        PrintFormat::Short => write!(w, "           ")?,
    }

    let file = std::str::from_utf8(file).unwrap_or("<unknown>");
    let file_path = Path::new(file);
    let mut already_printed = false;
    if format == PrintFormat::Short && file_path.is_absolute() {
        if let Ok(cwd) = env::current_dir() {
            if let Ok(stripped) = file_path.strip_prefix(&cwd) {
                if let Some(s) = stripped.to_str() {
                    write!(w, "  at .{}{}:{}", path::MAIN_SEPARATOR, s, line)?;
                    already_printed = true;
                }
            }
        }
    }
    if !already_printed {
        write!(w, "  at {}:{}", file, line)?;
    }

    w.write_all(b"\n")
}
