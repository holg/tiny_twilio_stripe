// --- File: src/calendly/calendly_oauth.rs ---

// Only compile this module if the 'calendly' feature is enabled
#![cfg(feature = "calendly")]

// --- Imports ---
use actix_web::{web, Responder, HttpResponse, Result as ActixResult, get, http::header, error, HttpRequest};
use oauth2::{
    AuthorizationCode, CsrfToken, Scope, TokenResponse,
    // reqwest as oauth2_reqwest, // Keep if using the helper function below
    HttpRequest as OAuth2Request,
    HttpResponse as OAuth2Response,
    HttpClientError as OAuth2HttpClientError //, StandardErrorResponse, RequestTokenError
};
use reqwest::{Client as ReqwestClient, Error as ReqwestError};
use serde::Deserialize;
use crate::config::AppConfig;
use chrono::{Utc, Duration as ChronoDuration};
#[allow(unused_imports)]
use crate::utils::sqlx_helper;
// Import cookie handling types
#[allow(unused_imports)]
use cookie::{Cookie, CookieJar, Key as CookieSignKey, SameSite};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as base64_engine};
// Import http types used by async_http_client
#[allow(unused_imports)]
use http::{Response as HttpResponseBuilder, HeaderMap, StatusCode};
use std::sync::Arc; // Needed for Arc<dyn Trait>
// Import the TokenStore trait and potentially StorageError
#[allow(unused_imports)]
use crate::storage::{TokenStore, StorageError}; // Adjust path if needed


// --- Structures ---
#[derive(Deserialize, Debug)]
struct AuthCallbackQuery { code: String, state: String }

// --- HTTP Client for oauth2 ---
// Implementation of the required async HTTP client function using reqwest
async fn async_http_client(
    request: OAuth2Request, // The request built by the oauth2 crate
) -> Result<OAuth2Response, OAuth2HttpClientError<ReqwestError>> {
    // Create a new reqwest client for each request
    let client = ReqwestClient::new();

    // Extract parts from the oauth2::HttpRequest
    let method = request.method().clone();
    let uri = request.uri().to_string();
    let headers = request.headers().clone();
    let body = request.body().clone();

    // Build the reqwest request
    let mut req_builder = client
        .request(method, &uri)
        .headers(headers); // Pass headers

    // Add body if present
    if !body.is_empty() {
        req_builder = req_builder.body(body);
    }

    // Send the request using reqwest
    let response = req_builder
        .send()
        .await
        // Map reqwest errors into the oauth2 crate's expected error type
        .map_err(|e| OAuth2HttpClientError::Reqwest(Box::new(e)))?;

    // Extract parts from the reqwest response
    let status = response.status();
    let resp_headers = response.headers().clone();
    // Read body as bytes
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| OAuth2HttpClientError::Reqwest(Box::new(e)))?
        .to_vec();

    // Construct the http::Response expected by the oauth2 crate
    let mut builder = HttpResponseBuilder::builder()
        .status(status);

    // Copy headers from reqwest response to http::Response builder
    let Some(builder_headers) = builder.headers_mut() else {
        // This should generally not fail unless builder is in a weird state
        return Err(OAuth2HttpClientError::Other("Failed to access response builder headers".into()));
    };
    *builder_headers = resp_headers;

    // Build the final http::Response with the body bytes
    let final_response = builder
        .body(body_bytes)
        .map_err(|e| OAuth2HttpClientError::Other(format!("Failed to build response: {e}").into()))?;

    // Return the http::Response
    Ok(final_response)
}

// --- Constants ---
const CSRF_COOKIE_NAME: &str = "calendly_csrf_state";

// --- Public Handler Functions ---

#[get("/auth/calendly/start")]
pub async fn start_calendly_auth(config: web::Data<AppConfig>) -> ActixResult<impl Responder> {
    // Check if needed config is present
    let Some(csrf_key) = config.csrf_state_key.as_ref() else {
        eprintln!("CSRF State Key missing in config for auth start.");
        return Err(error::ErrorInternalServerError("Server configuration error (csrf key)"));
    };
    let Some(client) = config.calendly_oauth_client() else {
        eprintln!("Calendly OAuth client not available in start, config likely missing.");
        return Err(error::ErrorInternalServerError("Server configuration error (client init)"));
    };

    // Generate URL and State
    let (authorize_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("default".to_string())) // Request appropriate scopes from Calendly
        .url();

    // Create and Sign CSRF State Cookie
    let state_value = csrf_token.secret().to_string();
    let encoded_state = base64_engine.encode(state_value); // Use base64 for cookie value
    let mut jar = CookieJar::new(); // Create a temporary jar for this response

    // Add the signed cookie to the jar
    jar.private_mut(&csrf_key).add(
        Cookie::build(CSRF_COOKIE_NAME, encoded_state.clone()) // Build the cookie using correct syntax
            .path("/") // Available on the whole site
            .secure(true) // Should be true if served over HTTPS
            .http_only(true) // Not accessible by client-side script
            .same_site(SameSite::Lax) // Good default for OAuth callbacks
            .max_age(cookie::time::Duration::minutes(10)) // Short expiry for state
            .finish() // Finalize cookie
    );

    // Build the redirect response
    let mut response_builder = HttpResponse::Found();
    // Set the redirect location header
    response_builder.append_header((header::LOCATION, authorize_url.to_string()));
    // Add the Set-Cookie header(s) from the jar
    for cookie in jar.delta() {
        response_builder.cookie(cookie.clone());
    }

    println!("CSRF State generated and set in cookie.");
    // Return the redirect response
    Ok(response_builder.finish())
}

#[get("/api/calendly/auth/")]
pub async fn calendly_auth_callback(
    req: HttpRequest,
    query: web::Query<AuthCallbackQuery>,
    config: web::Data<AppConfig>,
    token_store: web::Data<Arc<dyn TokenStore>>, // <--- comes from main.rs now
) -> ActixResult<impl Responder> {
    println!("Received callback: code=..., state={}", query.state); // Log state, avoid logging code

    // --- Validate CSRF State ---
    let Some(csrf_key) = config.csrf_state_key.as_ref() else {
        eprintln!("CSRF State Key missing in config for callback.");
        // Return generic error to user
        return Err(error::ErrorBadRequest("Invalid session state (csrf config missing)"));
    };

    // Create a jar to manage request cookies and prepare removal cookie
    let mut jar = CookieJar::new();
    // Parse cookies from the incoming request header
    if let Some(cookie_header) = req.headers().get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie_pair in cookie_str.split(';') {
                if let Ok(cookie) = Cookie::parse_encoded(cookie_pair.trim()) {
                    jar.add_original(cookie.into_owned()); // Add parsed cookie to jar
                }
            }
        }
    }

    // Attempt to retrieve the signed state cookie using the key
    let state_cookie = jar.private_mut(&csrf_key).get(CSRF_COOKIE_NAME);

    // Prepare a cookie to remove the state cookie from the browser later
    let removal_cookie = Cookie::build(CSRF_COOKIE_NAME, "").path("/").max_age(cookie::time::Duration::ZERO).finish(); // Need value for build

    // Validate the cookie exists and signature is valid
    let stored_encoded_state = match state_cookie {
        Some(cookie) => cookie.value().to_string(), // Get the encoded value
        None => {
            eprintln!("CSRF state cookie missing or invalid signature.");
            let mut resp = HttpResponse::BadRequest();
            // Try to remove potentially invalid cookie from browser
            jar.private_mut(&csrf_key).remove(removal_cookie.clone());
            for cookie_resp in jar.delta() { resp.cookie(cookie_resp.clone()); }
            return Ok(resp.body("Invalid session state (CSRF cookie missing/invalid)"));
        }
    };

    // Remove the cookie from our jar now that we have the value (it's one-time use)
    jar.private_mut(&csrf_key).remove(removal_cookie.clone());

    // Decode the state value stored in the cookie
    let stored_state = match base64_engine.decode(&stored_encoded_state) {
        Ok(decoded_bytes) => String::from_utf8(decoded_bytes)
            // If decoding works but bytes aren't UTF-8, treat as bad request
            .map_err(|_| error::ErrorBadRequest("Invalid encoding in state cookie"))?,
        Err(_) => {
            eprintln!("Failed to decode base64 state from cookie.");
            let mut resp = HttpResponse::BadRequest();
            // Add removal cookie header even if decoding failed
            for cookie_resp in jar.delta() { resp.cookie(cookie_resp.clone()); }
            return Ok(resp.body("Invalid session state (encoding)"));
        }
    };

    // Compare the state from the query parameter with the state from the cookie
    if stored_state != query.state {
        eprintln!("CSRF state mismatch: query='{}', cookie='{}'", query.state, stored_state);
        let mut resp = HttpResponse::BadRequest();
        // Add removal cookie header on mismatch
        for cookie_resp in jar.delta() { resp.cookie(cookie_resp.clone()); }
        return Ok(resp.body("Invalid state parameter (CSRF protection)"));
    }
    println!("CSRF state validated successfully.");
    // --- End State Validation ---

    // --- Proceed with Token Exchange ---
    // Check other necessary config is present
    let Some(encryption_key_ref) = config.encryption_key.as_deref() else {
        eprintln!("Encryption key missing in config for callback.");
        return Err(error::ErrorInternalServerError("Server configuration error (enc key)"));
    };
    let Some(client) = config.calendly_oauth_client() else {
        eprintln!("Calendly OAuth client not available in callback.");
        return Err(error::ErrorInternalServerError("Server configuration error (client init)"));
    };

    // Create AuthorizationCode from the query parameter
    let code = AuthorizationCode::new(query.code.clone());

    // Exchange the authorization code for access/refresh tokens
    match client.exchange_code(code).request_async(&async_http_client).await {
        Ok(token_response) => {
            // Successfully exchanged code, extract token details
            let access_token = token_response.access_token().secret();
            let refresh_token_opt = token_response.refresh_token();
            let expires_in_opt = token_response.expires_in(); // This is std::time::Duration

            println!("Access Token obtained (partially hidden).");

            // --- Encrypt Tokens ---
            let user_identifier = "default_calendly_user"; // TODO: Replace placeholder with real user ID
            let service_name = "calendly";

            // Encrypt access token
            let encrypted_access_token = match crate::utils::crypto::encrypt(encryption_key_ref, access_token.as_bytes()) {
                Ok(et) => et,
                Err(e) => {
                    eprintln!("Failed to encrypt access token: {}", e);
                    let mut resp = HttpResponse::InternalServerError();
                    // Add removal cookie header to error response
                    for cookie in jar.delta() { resp.cookie(cookie.clone()); }
                    return Ok(resp.body("Internal error during token processing (enc access)"));
                }
            };

            // Encrypt refresh token if present
            let encrypted_refresh_token: Option<Vec<u8>> = match refresh_token_opt {
                Some(rt) => match crate::utils::crypto::encrypt(encryption_key_ref, rt.secret().as_bytes()) {
                    Ok(et) => Some(et),
                    Err(e) => {
                        eprintln!("Failed to encrypt refresh token: {}", e);
                        let mut resp = HttpResponse::InternalServerError();
                        // Add removal cookie header to error response
                        for cookie in jar.delta() { resp.cookie(cookie.clone()); }
                        return Ok(resp.body("Internal error during token processing (enc refresh)"));
                    }
                },
                None => None, // No refresh token provided
            };

            // Calculate expiry timestamp (seconds since epoch)
            let expires_at: Option<i64> = expires_in_opt
                // Convert std::time::Duration to chrono::Duration, handle potential error
                .and_then(|duration| ChronoDuration::from_std(duration).ok())
                // Add duration to current time, handle potential error
                .and_then(|chrono_duration| Utc::now().checked_add_signed(chrono_duration))
                // Convert to Unix timestamp
                .map(|dt| dt.timestamp());

            // --- Store Tokens using TokenStore Trait ---
            // Call method on the injected token_store object
            let save_result = token_store.save_token(
                user_identifier,
                service_name,
                &encrypted_access_token, // Pass slice of encrypted data
                encrypted_refresh_token.as_deref(), // Pass Option<&[u8]>
                expires_at
            ).await; // await the trait method
            // --- End Store Tokens ---

            // --- Handle DB Result and Build Response ---
            let mut final_response_builder;
            let response_body: String;
            match save_result { // Check result from trait method save_token
                Ok(()) => { // Success is Ok(())
                    println!("Successfully stored/updated Calendly tokens via TokenStore for user: {}", user_identifier);
                    final_response_builder = HttpResponse::Ok();
                    response_body = "Successfully obtained and stored Calendly tokens! You can close this window.".to_string();
                }
                Err(e) => {
                    // Log the StorageError
                    eprintln!("TokenStore saving token failed: {}", e);
                    final_response_builder = HttpResponse::InternalServerError();
                    response_body = "Failed to save authentication details".to_string();
                }
            }
            // Add removal cookie header to final response
            for cookie_resp in jar.delta() {
                final_response_builder.cookie(cookie_resp.clone());
            }
            Ok(final_response_builder.body(response_body))
            // --- End Handle DB Result ---
        }
        Err(e) => {
            // Handle error during the token exchange request itself
            eprintln!("Error exchanging code for token: {:?}", e);
            let mut error_response = HttpResponse::InternalServerError();
            // Also remove cookie on token exchange error
            for cookie_resp in jar.delta() {
                error_response.cookie(cookie_resp.clone());
            }
            Ok(error_response.body(format!("Failed to exchange authorization code: {:?}", e)))
        }
    }
}


async fn load_and_decrypt_access_token(
    token_store: Arc<dyn TokenStore>,
    user_id: &str,
    service: &str,
    encryption_key: &[u8],
) -> Result<String, String> {
    let token_record = token_store.get_token(user_id, service)
        .await
        .map_err(|e| format!("Failed to load token: {}", e))?
        .ok_or_else(|| "No token found".to_string())?;

    let decrypted = crate::utils::crypto::decrypt(encryption_key, &token_record.access_token_encrypted)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(decrypted).map_err(|e| format!("Invalid UTF-8: {}", e))
}