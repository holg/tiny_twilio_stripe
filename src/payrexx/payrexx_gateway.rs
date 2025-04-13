use actix_web::{post, web, HttpResponse, Responder, Result as ActixResult};
use reqwest::Client;
use serde::{Deserialize, Serialize}; // Import both
use std::env;
use chrono::Utc;
use crate::utils::ensure_dotenv_loaded;

/// Represents the configuration required for Payrexx API access.
/// Loaded from environment variables when the `payrexx` feature is active.
#[derive(Clone, Debug)]
pub struct PayrexxConfig {
    /// Payrexx instance name (subdomain).
    pub instance_name: String,
    /// Payrexx API Secret.
    pub api_secret: String,
    /// URL template for successful payment redirection.
    pub success_url_template: String,
    /// URL for failed payment redirection.
    pub failed_url: String,
    /// URL for cancellation redirection.
    pub cancel_url: String,
    /// Payment currency code.
    pub currency: String,
    /// Payment amount in smallest currency unit.
    pub unit_amount: i32,
    /// Name/Purpose displayed for the payment.
    pub product_name: String,
}

impl PayrexxConfig {
    /// Loads the Payrexx configuration from environment variables.
    ///
    /// Expects variables like `PAYREXX_INSTANCE_NAME`, `PAYREXX_API_SECRET`, etc.
    /// Uses defaults for currency, amount, and product name if not set.
    /// Returns an error string if required variables are missing.
    pub fn load() -> Result<Self, String> {
        // ... (implementation as before)
        ensure_dotenv_loaded();
        let instance_name = env::var("PAYREXX_INSTANCE_NAME")
            .map_err(|_| "Missing PAYREXX_INSTANCE_NAME env var".to_string())?;
        let api_secret = env::var("PAYREXX_API_SECRET")
            .map_err(|_| "Missing PAYREXX_API_SECRET env var".to_string())?;
        let success_url_template = env::var("PAYREXX_SUCCESS_URL")
            .map_err(|_| "Missing PAYREXX_SUCCESS_URL env var".to_string())?;
        let failed_url = env::var("PAYREXX_FAILED_URL")
            .map_err(|_| "Missing PAYREXX_FAILED_URL env var".to_string())?;
        let cancel_url = env::var("PAYREXX_CANCEL_URL")
            .map_err(|_| "Missing PAYREXX_CANCEL_URL env var".to_string())?;
        let currency = env::var("PAYREXX_CURRENCY")
            .unwrap_or_else(|_| "CHF".to_string())
            .to_uppercase();
        let unit_amount_str = env::var("PAYREXX_UNIT_AMOUNT")
            .unwrap_or_else(|_| "1000".to_string());
        let unit_amount = unit_amount_str.parse::<i32>()
            .map_err(|_| format!("Invalid PAYREXX_UNIT_AMOUNT: {}", unit_amount_str))?;
        let product_name = env::var("PAYREXX_PRODUCT_NAME")
            .unwrap_or_else(|_| "Private Video Call".to_string());

        Ok(Self {
            instance_name,
            api_secret,
            success_url_template,
            failed_url,
            cancel_url,
            currency,
            unit_amount,
            product_name,
        })
    }
}

/// Represents a request to create a Payrexx Gateway.
/// Matches the structure of the Stripe CheckoutRequest for consistency.
/// Expected JSON body for the `/api/create-payrexx-gateway` endpoint.
#[derive(Deserialize, Debug)]
pub struct GatewayRequest {
    /// Name of the room, used for success/cancel URLs.
    pub room_name: String,
    /// User identity, used for success/cancel URLs.
    pub identity: String,
}

/// Represents the payload structure sent to the Payrexx Gateway API.
/// This struct is serialized to JSON for the request body.
#[derive(Serialize, Debug)] // Added Serialize
struct PayrexxGatewayApiRequest {
    amount: i32,
    currency: String,
    purpose: String,
    #[serde(rename = "referenceId")] // Keep camelCase for Payrexx API
    reference_id: String,
    #[serde(rename = "successRedirectUrl")] // Add rename for camelCase
    success_redirect_url: String,
    #[serde(rename = "failedRedirectUrl")] // Add rename for camelCase
    failed_redirect_url: String,
    #[serde(rename = "cancelRedirectUrl")] // Add rename for camelCase
    cancel_redirect_url: String,
    // Add other optional fields if needed, e.g., psp, pm, fields
    // "fields": { "email": { "value": "customer@example.com" } }
}

/// Represents the `data` object within the Payrexx API response.
/// This struct is deserialized from the Payrexx JSON response.
#[derive(Deserialize, Debug)]
struct PayrexxGatewayApiResponseData {
    // id: i32,
    // hash: String,
    /// The payment link URL generated by Payrexx.
    link: String,
    // Add other fields if needed
}

/// Represents the overall structure of the Payrexx API response.
/// This struct is deserialized from the Payrexx JSON response.
#[derive(Deserialize, Debug)]
struct PayrexxApiResponse {
    status: String,
    /// Payrexx returns the gateway data within an array.
    data: Vec<PayrexxGatewayApiResponseData>,
    message: Option<String>, // Capture potential error messages
}

/// Represents the response sent back to the client containing the gateway URL.
/// This struct is serialized to JSON for the `/api/create-payrexx-gateway` response.
#[derive(Serialize, Debug)] // Added Serialize
pub struct GatewayResponse {
    /// The URL for the Payrexx payment page.
    url: String,
}

/// Creates a Payrexx Gateway for a one-time payment.
///
/// Endpoint: `POST /api/create-payrexx-gateway`
///
/// Takes room and identity information, calls the Payrexx API to generate
/// a payment link (Gateway), and returns that link to the client.
/// Requires `PayrexxConfig` and `reqwest::Client` to be available in Actix app data.
#[post("/api/create-payrexx-gateway")]
pub async fn create_payrexx_gateway(
    req: web::Json<GatewayRequest>,
    client: web::Data<Client>,
    config: web::Data<PayrexxConfig>,
) -> ActixResult<impl Responder> {
    // ... (implementation as before, using corrected logic) ...
    println!("Received Payrexx gateway request for room: {}, identity: {}", req.room_name, req.identity);

    let success_url = config.success_url_template
        .replace("{room}", &req.room_name)
        .replace("{identity}", &req.identity);

    let reference_id = format!("twilio-room-{}-{}", req.room_name, Utc::now().timestamp_millis());

    let api_payload = PayrexxGatewayApiRequest {
        amount: config.unit_amount,
        currency: config.currency.clone(),
        purpose: config.product_name.clone(),
        reference_id,
        success_redirect_url: success_url,
        failed_redirect_url: config.failed_url.clone(),
        cancel_redirect_url: config.cancel_url.clone(),
    };

    let api_url = format!(
        "https://api.payrexx.com/v1.0/Gateway/?instance={}",
        config.instance_name
    );

    println!("Sending request to Payrexx API: {}", api_url);

    let response = client
        .post(&api_url)
        // Check Payrexx API Docs for current authentication method:
        // Option 1: Api-Secret Header
        .header("Api-Secret", &config.api_secret)
        // Option 2: Basic Auth (Username empty, Password is API Secret)
        // .basic_auth("", Some(&config.api_secret))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&api_payload)
        .send()
        .await;

    match response {
        Ok(res) => {
            let status = res.status();
            match res.text().await {
                Ok(body_text) => {
                    println!("Payrexx API response status: {}", status);
                    println!("Payrexx API response body: {}", body_text);

                    if status.is_success() {
                        match serde_json::from_str::<PayrexxApiResponse>(&body_text) {
                            Ok(payrexx_response) => {
                                if payrexx_response.status == "success" && !payrexx_response.data.is_empty() {
                                    let payment_link = payrexx_response.data[0].link.clone();
                                    println!("Payrexx gateway created successfully. Link: {}", payment_link);
                                    Ok(HttpResponse::Ok().json(GatewayResponse { url: payment_link }))
                                } else {
                                    let error_message = payrexx_response.message.unwrap_or_else(|| body_text.clone());
                                    eprintln!("Payrexx API reported error. Status: {}, Message: {}", payrexx_response.status, error_message);
                                    Ok(HttpResponse::InternalServerError().body(format!("Payrexx API Error: {}", error_message)))
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to parse Payrexx success response: {}. Body: {}", e, body_text);
                                Ok(HttpResponse::InternalServerError().body("Failed to parse Payrexx response"))
                            }
                        }
                    } else {
                        eprintln!("Payrexx API request failed with HTTP status: {}. Body: {}", status, body_text);
                        Ok(HttpResponse::InternalServerError().body(format!("Payrexx API request failed: {}", body_text)))
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read Payrexx response body: {}", e);
                    Ok(HttpResponse::InternalServerError().body("Failed to read Payrexx response body"))
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to send request to Payrexx API: {}", e);
            Ok(HttpResponse::InternalServerError().body("Failed to connect to Payrexx API"))
        }
    }
}