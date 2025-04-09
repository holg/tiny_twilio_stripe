use actix_web::{web, Responder, HttpResponse, Result as ActixResult};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use chrono::{Utc, Duration};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::utils::ensure_dotenv_loaded;

/// Represents the configuration required for Twilio API access.
///
/// This struct holds the necessary credentials to authenticate and interact
/// with Twilio's services. It includes the account SID, API key SID, and
/// API key secret, which are essential for generating access tokens and
/// making API requests.
///
/// # Fields
///
/// - `account_sid`: A `String` representing the Twilio account SID. This is
///   a unique identifier for the Twilio account.
/// - `api_key_sid`: A `String` representing the Twilio API key SID. This is
///   used to identify the API key being used.
/// - `api_key_secret`: A `String` representing the Twilio API key secret.
///   This is used to sign requests and generate tokens.
#[derive(Clone)]
pub struct TwilioConfig {
    pub account_sid: String,
    pub api_key_sid: String,
    pub api_key_secret: String,
}

impl TwilioConfig {
    /// Loads the Twilio configuration from environment variables.
    ///
    /// This function attempts to retrieve the Twilio account SID, API key SID,
    /// and API key secret from the environment variables `TWILIO_ACCOUNT_SID`,
    /// `TWILIO_API_KEY_SID`, and `TWILIO_API_KEY_SECRET`, respectively.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `TwilioConfig` instance if successful, or a
    /// `String` with an error message if any of the required environment
    /// variables are missing.
    pub fn load() -> Result<Self, String> {
        ensure_dotenv_loaded();
        let account_sid = env::var("TWILIO_ACCOUNT_SID")
            .map_err(|_| "Missing TWILIO_ACCOUNT_SID env var".to_string())?;
        let api_key_sid = env::var("TWILIO_API_KEY_SID")
            .map_err(|_| "Missing TWILIO_API_KEY_SID env var".to_string())?;
        let api_key_secret = env::var("TWILIO_API_KEY_SECRET")
            .map_err(|_| "Missing TWILIO_API_KEY_SECRET env var".to_string())?;

        Ok(Self {
            account_sid,
            api_key_sid,
            api_key_secret,
        })
    }
}

/// Represents a video grant for a Twilio access token.
///
/// This struct is used to specify the room for which the Twilio access token
/// is valid. It is included as part of the grants in the token's claims.
///
/// # Fields
///
/// - `room`: An `Option<String>` representing the name of the room for which
///   the token is valid. If `None`, the token is not restricted to a specific room.
#[derive(Debug, Serialize, Deserialize)]
struct VideoGrant {
    room: Option<String>,
}

/// Represents the grants included in a Twilio access token.
///
/// This struct is used to serialize and deserialize the grants that are
/// included in a Twilio access token. It includes the identity of the user
/// and the video grant, which specifies the room for which the token is valid.
///
/// # Fields
///
/// - `identity`: A `String` representing the identity of the user for whom
///   the token is being generated.
/// - `video`: A `VideoGrant` struct representing the video grant, which
///   includes the room name for which the token is valid.
#[derive(Debug, Serialize, Deserialize)]
struct Grants {
    identity: String,
    video: VideoGrant,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    exp: usize,
    jti: String,
    aud: String,
    grants: Grants,
}

/// Represents the query parameters for a token request.
///
/// This struct is used to deserialize the query parameters from a request
/// that is used to generate a Twilio access token. It includes the identity
/// of the user and the name of the room for which the token is being generated.
///
/// # Fields
///
/// - `identity`: A `String` representing the identity of the user for whom
///   the token is being generated.
/// - `room_name`: A `String` representing the name of the room for which
///   the token is being generated. This field is renamed to "roomName" in
///   the query parameters.
#[derive(Deserialize)]
pub struct TokenRequestQuery {
    pub identity: String,
    #[serde(rename = "roomName")]
    pub room_name: String,
}

/// Represents the response containing a Twilio access token.
///
/// This struct is used to serialize the response that includes the
/// generated Twilio access token as a JSON object.
///
/// # Fields
///
/// - `token`: A `String` representing the generated Twilio access token.
#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
}

/// Generates a Twilio access token for video services.
///
/// This function creates a JWT token that can be used to authenticate
/// with Twilio's video services. The token includes claims for the
/// specified identity and room name, and is signed using the Twilio
/// API key secret.
///
/// # Parameters
///
/// - `query`: A `web::Query<TokenRequestQuery>` containing the identity
///   and room name for which the token is being generated.
/// - `config`: A `web::Data<TwilioConfig>` containing the Twilio
///   configuration, including account SID, API key SID, and API key secret.
///
/// # Returns
///
/// An `ActixResult` containing an `impl Responder`. On success, it returns
/// an `HttpResponse::Ok` with a JSON body containing the generated token.
/// On failure, it returns an `HttpResponse::InternalServerError` with an
/// error message.
pub async fn generate_token(
    query: web::Query<TokenRequestQuery>,
    config: web::Data<TwilioConfig>,
) -> ActixResult<impl Responder> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let jti = format!("{}-{}", config.api_key_sid, now_secs);

    let expiry_seconds: i64 = env::var("TOKEN_EXPIRY")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(3600);

    let expiration = (Utc::now() + Duration::seconds(expiry_seconds)).timestamp() as usize;

    let claims = Claims {
        sub: config.account_sid.clone(),
        iss: config.api_key_sid.clone(),
        aud: "https://video.twilio.com".to_string(),
        exp: expiration,
        jti,
        grants: Grants {
            identity: query.identity.clone(),
            video: VideoGrant {
                room: Some(query.room_name.clone()),
            },
        },
    };

    println!("DEBUG: Generating token with iss(SK): {}, sub(AC): {}", claims.iss, claims.sub);

    let mut header = Header::new(Algorithm::HS256);
    header.cty = Some("twilio-fpa;v=1".to_string());
    header.typ = Some("JWT".to_string());

    match encode(&header, &claims, &EncodingKey::from_secret(config.api_key_secret.as_ref())) {
        Ok(token) => Ok(HttpResponse::Ok().json(TokenResponse { token })),
        Err(e) => {
            eprintln!("Error generating token: {}", e);
            Ok(HttpResponse::InternalServerError().body("Failed to generate token"))
        }
    }
}
