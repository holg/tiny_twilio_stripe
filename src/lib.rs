//! # tiny_twilio_stripe
//!
//! `tiny_twilio_stripe` is an extensible Actix-Web backend for generating [Twilio Video](https://www.twilio.com/video) tokens,
//! and optionally initiating [Stripe Checkout](https://stripe.com/docs/payments/checkout) sessions.
//!
//! ## ✅ Features
//!
//! - 🎥 Generate secure Twilio JWT tokens for video rooms
//! - 💰 Optional Stripe Checkout endpoint
//! - 🔐 Rate limiting with `actix-governor`
//! - 🧪 Environment file support (`.env`, `.env.production`, etc.)
//!
//! ## 🔧 Configuration
//!
//! Start the app like this:
//!
//! ```bash
//! cargo run -- .env.production
//! ```
//!
//! ### Required `.env` values (Twilio)
//!
//! - `TWILIO_ACCOUNT_SID`
//! - `TWILIO_API_KEY_SID`
//! - `TWILIO_API_KEY_SECRET`
//! - `TOKEN_EXPIRY=3600` (optional, default: 3600s)
//!
//! ### Stripe Settings (only if `--features stripe` is enabled)
//!
//! - `STRIPE_SECRET_KEY`
//! - `STRIPE_SUCCESS_URL=https://your.site/success?room={room}&identity={identity}`
//! - `STRIPE_CANCEL_URL=https://your.site/cancel`
//! - `STRIPE_CURRENCY=eur`
//! - `STRIPE_UNIT_AMOUNT=1000`
//! - `STRIPE_PRODUCT_NAME=Private Video Call`
//!
//! ### Rate Limiting
//!
//! - `GOVERNOR_BURST=5`
//! - `GOVERNOR_PER_SECOND=2`
//!
//! ## ✨ Feature Flags
//!
//! - `stripe`: Enables the `/api/create-checkout-session` endpoint.
//!
//! ## 📚 Modules
//!
//! - [`twilio`](crate::twilio) — Twilio token generation
//! - [`utils`](crate::utils) — Environment loader
//!
//! ### Stripe (conditionally included)
//!
//! - [`stripe`](crate::stripe) — Stripe Checkout handler *(only with `--features stripe`)*
//!
//! ## 📄 License
//!
//! MIT License © [Holger Trahe](https://github.com/holg)

pub mod twilio;
pub mod utils;

#[cfg(feature = "stripe")]
pub mod stripe;
