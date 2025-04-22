#[cfg(feature = "stripe")]
mod stripe;
mod twilio;
mod utils;

#[cfg(feature = "stripe")]
use reqwest::Client;
#[cfg(feature = "stripe")]
use stripe::stripe_checkout::create_checkout_session_handler;

use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{web, App, HttpServer};
use std::env;
use twilio::twilio_token::{generate_token_handler, TwilioConfig};

/// The main entry point for the application.
///
/// This asynchronous function initializes the server by loading environment
/// variables, configuring the Twilio and Stripe services, and setting up
/// the HTTP server with the necessary routes and middleware.
///
/// # Parameters
///
/// This function does not take any parameters directly, but it reads
/// environment variables and command-line arguments:
///
/// - The first command-line argument is used to specify the path to the
///   environment file. If not provided, it defaults to `.env`.
///
/// # Returns
///
/// This function returns a `std::io::Result<()>`, which indicates the success
/// or failure of starting the HTTP server. A successful result means the server
/// has started and is running, while an error result indicates a failure to
/// bind the server to the specified address or other I/O errors.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 👇 Load env file from args
    let env_file = utils::ensure_dotenv_loaded();

    println!("📦 Loading environment from {env_file}");
    dotenv::from_filename(&env_file).expect("Failed to load specified .env file");

    let twilio_config = TwilioConfig::load().expect("Twilio config failed");

    let server_port: u16 = env::var("SERVER_PORT")
        .unwrap_or_else(|_| "6666".into())
        .parse()
        .expect("Invalid SERVER_PORT");

    println!("🚀 Server starting on http://127.0.0.1:{}", server_port);
    println!(
        "🔗 Test: http://127.0.0.1:{}/api/generate-token?identity=TestUser123&roomName=TestRoomABC",
        server_port
    );

    let use_stripe = env::var("USE_STRIPE")
        .unwrap_or_else(|_| "false".to_string())
        .eq_ignore_ascii_case("true");

    #[cfg(not(feature = "stripe"))]
    {
        if use_stripe {
            println!("⚠️  Stripe is requested (USE_STRIPE=true), but not compiled in. Rebuild with `--features stripe` to enable.");
        }
    }

    #[cfg(feature = "stripe")]
    {
        if !use_stripe {
            println!("ℹ️ Stripe is compiled in, but disabled via USE_STRIPE=false.");
        } else {
            println!("ℹ️ Using Stripe for checkout.");
        }
    }

    let governor_burst = env::var("GOVERNOR_BURST")
        .unwrap_or_else(|_| "5".into())
        .parse()
        .unwrap_or(5);
    let governor_per_sec = env::var("GOVERNOR_PER_SECOND")
        .unwrap_or_else(|_| "2".into())
        .parse()
        .unwrap_or(2);

    let governor_conf = GovernorConfigBuilder::default()
        .burst_size(governor_burst)
        .seconds_per_request(governor_per_sec)
        .finish()
        .expect("Failed to build governor config");

    HttpServer::new(move || {
        let app = App::new()
            .wrap(Governor::new(&governor_conf))
            .app_data(web::Data::new(twilio_config.clone()))
            .route("/api/generate-token", web::get().to(generate_token_handler));

        #[cfg(feature = "stripe")]
        {
            if use_stripe {
                let client = Client::new();
                return app
                    .app_data(web::Data::new(client))
                    .service(create_checkout_session_handler);
            }
        }

        app
    })
    .bind(("127.0.0.1", server_port))?
    .run()
    .await
}
