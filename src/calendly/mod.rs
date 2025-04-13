// --- File: src/calendly/mod.rs ---

// Only compile this module if the 'calendly' feature is enabled
#![cfg(feature = "calendly")]

// Declare the submodule containing the handlers
pub mod calendly_oauth;
// Re-export the public handlers for easier use from outside this module (e.g., from main.rs)
// This makes `calendly::start_calendly_auth` and `calendly::calendly_auth_callback` valid paths.
pub use calendly_oauth::{start_calendly_auth, calendly_auth_callback}; // <-- ADDED THIS LINE
