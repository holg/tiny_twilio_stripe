//! # Payrexx Module (Feature: `payrexx`)
//!
//! Provides functionality to interact with the Payrexx payment gateway API.
//! This module is only included when the `payrexx` feature is enabled.
#[cfg(feature = "payrexx")]
pub mod payrexx_gateway;
pub use payrexx_gateway::PayrexxConfig;