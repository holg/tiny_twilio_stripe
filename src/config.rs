// --- File: src/config.rs ---

use std::env;
// Import dependent config structs/types conditionally
#[cfg(feature = "payrexx")]
use crate::payrexx::payrexx_gateway::PayrexxConfig;
use crate::twilio::twilio_token::TwilioConfig;
#[cfg(feature = "calendly")]
use cookie::Key as CookieSignKey;
#[cfg(feature = "calendly")]
use hex;
#[cfg(feature = "calendly")]
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, EndpointNotSet, EndpointSet, RedirectUrl,
    TokenUrl,
};
// --- Unified Configuration Struct ---
#[derive(Clone)]
pub struct AppConfig {
    // --- Always Present Config ---
    pub server_port: u16,
    pub twilio_config: TwilioConfig,

    // --- Runtime Flags (Always present in struct) ---
    pub use_twilio: bool,
    pub use_stripe: bool,
    pub use_payrexx: bool,
    pub use_calendly: bool,

    // --- Optional Config Details (Exist only if feature compiled) ---
    #[cfg(feature = "payrexx")]
    pub payrexx_config: Option<PayrexxConfig>,

    #[cfg(feature = "calendly")]
    pub calendly_client_id: Option<ClientId>,
    #[cfg(feature = "calendly")]
    pub calendly_client_secret: Option<ClientSecret>,
    #[cfg(feature = "calendly")]
    pub calendly_redirect_uri: Option<RedirectUrl>,
    #[cfg(feature = "calendly")]
    pub calendly_auth_url: Option<AuthUrl>,
    #[cfg(feature = "calendly")]
    pub calendly_token_url: Option<TokenUrl>,
    // Conditionally include DB/Encryption fields only if calendly feature enabled
    #[cfg(feature = "calendly")]
    pub database_url: Option<String>, // Use Option<> as loading depends on use_calendly flag
    #[cfg(feature = "calendly")]
    pub encryption_key: Option<Vec<u8>>,
    #[cfg(feature = "calendly")]
    pub csrf_state_key: Option<CookieSignKey>,

    // Placeholder if no optional features are compiled
    #[cfg(all(
        not(feature = "payrexx"),
        not(feature = "calendly"),
        not(feature = "stripe")
    ))]
    _placeholder: (),
}

impl AppConfig {
    // Load configuration from environment variables
    pub fn load() -> Result<Self, String> {
        crate::utils::ensure_dotenv_loaded();

        // --- Load Runtime Flags First (Always attempt to load) ---
        let use_twilio = env::var("USE_TWILIO")
            .unwrap_or_else(|_| "true".to_string())
            .eq_ignore_ascii_case("true");
        let use_stripe = env::var("USE_STRIPE")
            .unwrap_or_else(|_| "false".to_string())
            .eq_ignore_ascii_case("true");
        let use_payrexx = env::var("USE_PAYREXX")
            .unwrap_or_else(|_| "false".to_string())
            .eq_ignore_ascii_case("true");
        let use_calendly = env::var("USE_CALENDLY")
            .unwrap_or_else(|_| "false".to_string())
            .eq_ignore_ascii_case("true");

        // --- Load Server Port ---
        let server_port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "6666".into())
            .parse::<u16>()
            .map_err(|_| "Invalid SERVER_PORT".to_string())?;

        // --- Load Twilio Config ---
        let twilio_config = TwilioConfig::load()?;

        // --- Load Payrexx Config Conditionally based on feature AND runtime flag ---
        #[cfg(feature = "payrexx")]
        let payrexx_config_loaded = {
            if use_payrexx {
                match crate::payrexx::PayrexxConfig::load() {
                    Ok(config) => Some(config),
                    Err(e) => {
                        eprintln!(
                            "🚨 Failed to load Payrexx config (required by USE_PAYREXX=true): {}",
                            e
                        );
                        None
                    }
                }
            } else {
                if cfg!(feature = "payrexx") {
                    println!(
                        "ℹ️ Payrexx feature compiled, but runtime disabled via USE_PAYREXX=false."
                    );
                }
                None
            }
        };
        // If feature not enabled, define placeholder and prefix with underscore
        #[cfg(not(feature = "payrexx"))]
        let _payrexx_config_loaded: Option<()> = None;

        #[cfg(feature = "calendly")]
        let (
            // This let binds a 6-element tuple
            calendly_client_id_loaded,
            calendly_client_secret_loaded,
            calendly_redirect_uri_loaded,
            calendly_auth_url_loaded,
            calendly_token_url_loaded,
            csrf_state_key_loaded, // Added csrf_state_key_loaded here
        ) = {
            if use_calendly {
                // Load CSRF key first
                let csrf_state_key = env::var("CSRF_STATE_SECRET").ok().and_then(|key_str| {
                    if key_str.len() < 32 {
                        eprintln!("⚠️ CSRF_STATE_SECRET is too short (recommend 64+ bytes).");
                        None
                    } else {
                        Some(CookieSignKey::from(key_str.as_bytes()))
                    }
                });
                if csrf_state_key.is_none() {
                    eprintln!("⚠️ CSRF_STATE_SECRET env var missing or too short.");
                }

                // Load other keys only if CSRF key is present (optional dependency)
                // You might adjust this if Calendly should still work partially without CSRF key
                if csrf_state_key.is_some() {
                    let client_id_res = env::var("CALENDLY_CLIENT_ID");
                    let client_secret_res = env::var("CALENDLY_CLIENT_SECRET");
                    let redirect_uri_res = env::var("CALENDLY_REDIRECT_URI");

                    if client_id_res.is_ok()
                        && client_secret_res.is_ok()
                        && redirect_uri_res.is_ok()
                    {
                        let client_id_str = client_id_res.unwrap();
                        let client_secret_str = client_secret_res.unwrap();
                        let redirect_uri_str = redirect_uri_res.unwrap();

                        let client_id = Some(ClientId::new(client_id_str));
                        let client_secret = Some(ClientSecret::new(client_secret_str));
                        let redirect_uri = RedirectUrl::new(redirect_uri_str).ok();
                        let auth_url =
                            AuthUrl::new("https://auth.calendly.com/oauth/authorize".to_string())
                                .ok();
                        let token_url =
                            TokenUrl::new("https://auth.calendly.com/oauth/token".to_string()).ok();

                        if redirect_uri.is_some() && auth_url.is_some() && token_url.is_some() {
                            // Return 6 elements on success
                            (
                                client_id,
                                client_secret,
                                redirect_uri,
                                auth_url,
                                token_url,
                                csrf_state_key,
                            )
                        } else {
                            eprintln!("⚠️ Failed to parse one or more Calendly URLs.");
                            // Return 6 Nones on URL parse failure
                            (None, None, None, None, None, None)
                        }
                    } else {
                        eprintln!("⚠️ Required Calendly client env vars missing.");
                        // Return 6 Nones if client env vars missing
                        (None, None, None, None, None, None)
                    }
                } else {
                    // Return 6 Nones if CSRF key missing
                    (None, None, None, None, None, None)
                }
            } else {
                // use_calendly is false
                if cfg!(feature = "calendly") {
                    println!("ℹ️ Calendly feature compiled, but runtime disabled via USE_CALENDLY=false.");
                }
                // Return 6 Nones if disabled via flag
                (None, None, None, None, None, None)
            }
        };
        // Define placeholders if feature is disabled (must match tuple size)
        #[cfg(not(feature = "calendly"))]
        let (
            _calendly_client_id_loaded, _calendly_client_secret_loaded, _calendly_redirect_uri_loaded,
            _calendly_auth_url_loaded, _calendly_token_url_loaded, _csrf_state_key_loaded // Added placeholder
        ): (Option<()>, Option<()>, Option<()>, Option<()>, Option<()>, Option<()>) // Added type
            = (None, None, None, None, None, None); // Added None

        // Construct the AppConfig instance using loaded values
        Ok(AppConfig {
            twilio_config,

            #[cfg(feature = "payrexx")]
            payrexx_config: payrexx_config_loaded,
            #[cfg(feature = "calendly")]
            calendly_client_id: calendly_client_id_loaded,
            #[cfg(feature = "calendly")]
            calendly_client_secret: calendly_client_secret_loaded,
            #[cfg(feature = "calendly")]
            calendly_redirect_uri: calendly_redirect_uri_loaded,
            #[cfg(feature = "calendly")]
            calendly_auth_url: calendly_auth_url_loaded,
            #[cfg(feature = "calendly")]
            calendly_token_url: calendly_token_url_loaded,
            #[cfg(feature = "calendly")]
            csrf_state_key: csrf_state_key_loaded,
            #[cfg(feature = "calendly")]
            database_url: {
                if use_calendly {
                    env::var("DATABASE_URL").ok()
                } else {
                    None
                }
            },
            #[cfg(feature = "calendly")]
            encryption_key: {
                if use_calendly {
                    match env::var("ENCRYPTION_KEY") {
                        Ok(key_str) => match hex::decode(key_str) {
                            Ok(key_bytes) => Some(key_bytes),
                            Err(_) => None,
                        },
                        Err(_) => None,
                    }
                } else {
                    None
                }
            },
            // Assign the runtime flags unconditionally
            use_twilio,
            use_stripe,
            use_payrexx,
            use_calendly,

            server_port,

            // Add placeholder only if NO optional features are compiled
            #[cfg(all(
                not(feature = "payrexx"),
                not(feature = "calendly"),
                not(feature = "stripe")
            ))]
            _placeholder: (),
        })
    }

    // Helper for Calendly OAuth client (only compile if feature enabled)
    #[cfg(feature = "calendly")]
    pub fn calendly_oauth_client(
        &self,
    ) -> Option<BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>>
    {
        // Check the runtime flag first
        if !self.use_calendly {
            return None;
        }
        // Then check if all required Option fields were loaded successfully
        if let (
            Some(client_id),
            Some(client_secret),
            Some(auth_url),
            Some(token_url),
            Some(redirect_uri),
        ) = (
            self.calendly_client_id.as_ref(),
            self.calendly_client_secret.as_ref(),
            self.calendly_auth_url.as_ref(),
            self.calendly_token_url.as_ref(),
            self.calendly_redirect_uri.as_ref(),
        ) {
            let client = BasicClient::new(client_id.clone())
                .set_client_secret(client_secret.clone())
                .set_auth_uri(auth_url.clone())
                .set_token_uri(token_url.clone())
                .set_redirect_uri(redirect_uri.clone());
            Some(client)
        } else {
            None
        }
    }
}
