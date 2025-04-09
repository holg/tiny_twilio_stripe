# 🛠️ Twilio Rust Video Token & Stripe Checkout Server

This is a lightweight, production-ready Rust-based Actix Web server that:

- 🔐 Generates [Twilio Video](https://www.twilio.com/video) JWT tokens for
  secure room access.
- 💳 Optionally integrates with
  [Stripe Checkout](https://stripe.com/docs/payments/checkout) for paid video
  sessions.
- 🌱 Uses `.env` for configuration and supports feature flags for flexible
  builds.

---

## 🚀 Features

- ✅ Twilio Video token endpoint (`/api/generate-token`)
- ✅ Optional Stripe checkout endpoint (`/api/create-checkout-session`)
- 🧩 Modular structure (Twilio & Stripe code separated)
- 🔐 JWTs with video grants & expiration
- ⚙️ Configurable via `.env`
- 📦 Single-binary friendly (no Redis required)
- 🌐 Ready to deploy behind Nginx, Caddy, etc.
- 🔐 Uses rusttls instead of openssl, as such it is easy to cross-compile
- ⚙️ generate the Debian x86_64 binaries e.g. macos)

---

## 📦 Requirements

- Rust 2021+
- Twilio account (API SID, secret)
- Optional: Stripe account (secret key)

---

## 🔧 Setup

1. **Clone this repo**
2. **Create `.env` file:**

   ```env
   SERVER_PORT=8888
   USE_STRIPE=false

   GOVERNOR_BURST=5
   GOVERNOR_PER_SECOND=2
   # 60*60s = 3,600s => 1h
   TOKEN_EXPIRY=3600

   # Twilio configuration
   TWILIO_ACCOUNT_SID=ACxxx...
   TWILIO_API_KEY_SID=SKxxx...
   TWILIO_API_KEY_SECRET=your_secret

   # Stripe (optional)
   USE_STRIPE=true
   STRIPE_SECRET_KEY=sk_test_xxx
   STRIPE_CURRENCY=EUR
   STRIPE_AMOUNT=1000
   STRIPE_PRODUCT_NAME=Private Video Session
   STRIPE_SUCCESS_URL=https://yourdomain.com/success
   STRIPE_CANCEL_URL=https://yourdomain.com/cancel
   ```

## ▶️ Run the Server

- Without Stripe support:
  ```bash
  cargo run
  ```
- With Stripe support:
  ```bash
  cargo run --features stripe
  ```
  optional pass the .env file e.g. `.env.production`

## 🔸 With Stripe support

`cargo run --features stripe` optional pass the .env file e.g. `.env.production`

## 📘 API

### GET /api/generate-token

Generates a Twilio JWT token for the given identity and room.

Query Parameters: •	identity – The user name •	roomName – Room to join

Example: GET /api/generate-token?identity=alice&roomName=room1

### Optional Stripe support

POST /api/create-checkout-session (requires Stripe + USE_STRIPE=true)

Creates a Stripe Checkout session.

JSON Body:

```
{
  "identity": "alice",
  "room_name": "room1"
}
```

Returns:

`{ "url": "https://checkout.stripe.com/session/..." }`

## 🧪 Testing

You can test endpoints using Postman or curl:

`curl "http://localhost:6666/api/generate-token?identity=test&roomName=myroom"`

## 🛡️ Security

•	Tokens expire after 1 hour default, but configurable in seconds in .env
TOKEN_EXPIRY •	Rate-limiting can be added via actix-governor

## 📁 Project Structure

```
tiny_twilio_stripe/
├── src/
│   ├── main.rs            # Actix server entry point
│   ├── twilio/
│   │   ├── mod.rs
│   │   └── twilio_token.rs
│   └── stripe/
│       ├── mod.rs
│       └── stripe_checkout.rs
├── .env
├── Cargo.toml
└── README.md
```

## 📜 License

[MIT](LICENCE)
