//! The pure decision logic of a supervised tunnel (ADR-0023).
//!
//! A supervised tunnel re-establishes its carrier after a connection loss
//! instead of ending. This module holds the three pieces that decide *when*
//! and *whether* to try again, with no socket, no task and no wall clock of
//! their own, so every rule is testable under `tokio::time::pause()` with a
//! seeded RNG:
//!
//! - [`backoff`]: how long to wait between attempts (decision 10, 18): a
//!   500 ms start doubling to 30 s, capped at 2 s inside a 60 s fast window
//!   that every loss and every wake reopens.
//! - [`budget`]: how long the tunnel may stay disconnected in total
//!   (decision 10): only disconnected time counts, and a re-established
//!   carrier must live 30 s before the loss is considered over.
//! - [`classify`]: which failures are worth another attempt (decision 9).
//!
//! The supervisor loop that drives them is a separate layer. The constants
//! here are fixed on purpose: they do not read `[reverse]` (that table
//! belongs to the target role) and are not opened up as configuration,
//! following ADR-0021 decision 4's rule of opening only values with a
//! demonstrated need.

// Nothing calls this module until the supervisor loop lands; the allowance
// goes away with the first caller.
#![cfg_attr(not(test), allow(dead_code))]

pub(crate) mod backoff;
pub(crate) mod budget;
pub(crate) mod classify;

#[cfg(test)]
mod tests;
