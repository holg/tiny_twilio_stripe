// tests/calendly_running_servet_test.rs

#![cfg(all(test, feature = "calendly"))]
mod common;
use common::{setup_test_app, load_test_token_store};
use reqwest::Client;
use actix_web::{test, web, App, http::StatusCode, http::header};
use std::{env, sync::Arc};
// Removed imports related to MockServer, Mock, ResponseTemplate, method, and path
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use cookie::{Cookie, CookieJar, Key as CookieSignKey, SameSite}; // ADDED
use base64::Engine; // ADDED
use cookie::Key; // ADDED

// Import items from your crate
use tiny_twilio_stripe::{
    config::AppConfig,
    calendly::{start_calendly_auth, calendly_auth_callback},
    storage::TokenStore,
    utils::sqlx_helper::create_sqlite_token_store
};

#[actix_web::test]
async fn test_start_calendly_auth_redirects() {
    env::set_var("DOTENV_OVERRIDE", ".env.test_calendly");
    let config = AppConfig::load().expect("Failed to load test config");
    assert!(config.calendly_client_id.is_some(), "Test requires Calendly env vars");
    assert!(config.database_url.is_some(), "Test requires DATABASE_URL"); // Added check
    let token_store = Arc::new(load_test_token_store().await);
    let app = setup_test_app(config.clone(), token_store.clone()).await;
    let req = test::TestRequest::get().uri("/auth/calendly/start").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp.headers().get(header::LOCATION).expect("Redirect location header missing");
    let location_str = location.to_str().unwrap();
    assert!(location_str.starts_with("https://auth.calendly.com/oauth/authorize"));
    assert!(location_str.contains(&format!("client_id={}", config.calendly_client_id.unwrap().as_str())));
    assert!(location_str.contains("state="));
    assert!(location_str.contains( &format!("redirect_uri={}", urlencoding::encode(config.calendly_redirect_uri.unwrap().as_str())) ));
}
