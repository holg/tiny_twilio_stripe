// tests/calendly.rs

#![cfg(all(test, feature = "calendly"))]

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
mod common;
use common::{setup_test_app, load_test_token_store};

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

#[actix_web::test]
async fn test_store_and_retrieve_token() {
    let token_store = load_test_token_store().await;

    // 3. Store dummy token
    let user_id = "test_user";
    let service = "calendly";
    let access_token = b"dummy_access";
    let refresh_token = Some(b"dummy_refresh".as_ref());
    let expires_at = Some(1_717_171_717);

    token_store
        .save_token(user_id, service, access_token, refresh_token, expires_at)
        .await
        .expect("Failed to save token");

    // 4. Retrieve and check
    let loaded = token_store
        .get_token(user_id, service)
        .await
        .expect("Failed to get token");

    assert!(loaded.is_some());
    let token = loaded.unwrap();
    assert_eq!(token.expires_at, expires_at);
    assert_eq!(token.refresh_token_encrypted.as_deref(), refresh_token);
}

#[actix_web::test]
async fn test_store_and_retrieve_token_encrypt_decrypt() {
    let token_store = load_test_token_store().await;

    let user_id = "test_user_encrypted";
    let service = "calendly";
    let access_token = "super_secret_token";
    let refresh_token = Some("super_secret_refresh_token");
    let expires_at = Some(1_717_171_717);

    token_store
        .save_token_encrypted(user_id, service, access_token, refresh_token, expires_at)
        .await
        .expect("Failed to save encrypted token");

    let result = token_store
        .get_token_decrypted(user_id, service)
        .await
        .expect("Failed to decrypt and get token");

    assert!(result.is_some());
    let (access, refresh, exp) = result.unwrap();
    assert_eq!(access, access_token);
    assert_eq!(refresh.as_deref(), refresh_token);
    assert_eq!(exp, expires_at);
}
// TODO: Add more tests
