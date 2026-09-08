//! CLI interface — arg parsing + orchestration.

pub mod args;
pub mod run;
pub mod validate;

pub use args::{Cli, Format, SortBy};
pub use run::run;
