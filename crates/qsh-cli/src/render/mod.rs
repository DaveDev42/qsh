//! Rendering: translates op results into either the `qsh.cli/v1` JSON
//! envelope ([`json`]) or human-readable text ([`human`]). Nothing outside
//! this module may format output for either mode.

pub mod human;
pub mod json;
