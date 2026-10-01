//! Binary entry point for `grip`.
//!
//! This file is intentionally tiny: all the logic lives in `grip::cli::run`
//! so it can be unit-tested without spawning a process. We parse `Cli`,
//! call `run`, and map errors to a pretty message + exit code.

use clap::Parser;
use grip::cli::Cli;

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let Err(e) = grip::cli::run(&cli) else {
        return std::process::ExitCode::SUCCESS;
    };

    eprintln!("error: {e}");
    // Exit 2 is reserved for a bad invocation, so scripts can tell "you asked
    // for something impossible" apart from "the probe itself failed".
    let code = if matches!(e, grip::error::GripError::InvalidArg(_)) {
        2
    } else {
        1
    };
    std::process::ExitCode::from(code)
}
