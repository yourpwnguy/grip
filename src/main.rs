//! Binary entry point for `grip`.
//!
//! This file is intentionally tiny — all logic lives in `grip::cli::run`
//! so it can be unit-tested without spawning a process. We parse `Cli`,
//! call `run`, and map errors to a pretty message + exit code.

use clap::Parser;
use grip::cli::Cli;

fn main() -> std::process::ExitCode {
    // Use `anstream` for color auto-detection; clap already respects NO_COLOR.
    let cli = Cli::parse();
    if let Err(e) = grip::cli::run(&cli) {
        // Print error to stderr with a consistent prefix.
        eprintln!("error: {e}");
        // Provide a hint for common cases.
        match e {
            grip::error::GripError::InvalidArg(_) => return std::process::ExitCode::from(2),
            _ => return std::process::ExitCode::from(1),
        }
    }
    std::process::ExitCode::SUCCESS
}
