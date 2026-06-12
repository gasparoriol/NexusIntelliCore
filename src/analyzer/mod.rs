// Shared types
#![allow(unused_imports)]
mod types;
pub use types::*;

// Public sub modules (for external consumers)
pub mod audit;
pub mod entrypoints;
pub mod lang;
pub mod patterns;
pub mod use_cases;

// Private sub modules (only accessed via parse.rs)
mod classes;
mod css;
mod docs;
mod functions;
mod html;
mod imports;
mod parse;
mod query;
mod strings;

// Re-exports of the public API
pub use audit::audit_file_ast;
pub use docs::{extract_module_doc, extract_preceding_comment};
pub use entrypoints::detect_entrypoints;
pub use functions::extract_signature;
pub use imports::classify_import_kind_from_path;
pub use lang::{detect_language, Lang};
pub use parse::analyze_file;
pub use patterns::detect_patterns;
pub use use_cases::infer_use_cases;

#[cfg(test)]
mod tests;
