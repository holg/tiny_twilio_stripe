// stripe_checkout.rs
use actix_web::{post, web, HttpResponse, Responder};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

/// Represents a request to create a Stripe checkout session.
///
/// This struct is used to deserialize the JSON payload received in the request
/// to create a Stripe checkout session. It contains the necessary information
/// about the room and the user identity.
///
/// # Fields
///
/// * `room_name` - The name of the room for which the checkout session is being created.
/// * `identity` - The identity of the user initiating the checkout session.
#[derive(Deserialize)]
pub struct CheckoutRequest {
    pub room_name: String,
    pub identity: String,
}

/// Represents the response from the Stripe API containing the checkout session URL.
///
/// This struct is used to serialize the JSON response that will be sent back to the client
/// after successfully creating a Stripe checkout session.
///
/// # Fields
///
/// * `url` - The URL of the created Stripe checkout session.
#[derive(Serialize)]
pub struct StripeResponse {
    url: String,
}

/// Creates a Stripe checkout session for a given room and identity.
///
/// This function handles the creation of a Stripe checkout session by sending a request
/// to the Stripe API. It constructs the necessary parameters for the session, including
/// success and cancel URLs, currency, unit amount, and product name. The function also
/// ensures that environment variables are loaded before proceeding.
///
/// # Parameters
///
/// * `req`: A JSON payload containing the `CheckoutRequest` which includes:
///   - `room_name`: The name of the room for which the checkout session is being created.
///   - `identity`: The identity of the user initiating the checkout session.
/// * `client`: An instance of `reqwest::Client` used to send HTTP requests.
///
/// # Returns
///
/// Returns an `impl Responder` which is an HTTP response. If successful, it returns a JSON
/// response containing the URL of the created Stripe checkout session. In case of an error,
/// it returns an HTTP 500 Internal Server Error with an appropriate error message.
#[post("/api/create-checkout-session")]
pub async fn create_checkout_session_handler(
    req: web::Json<CheckoutRequest>,
    client: web::Data<Client>,
) -> impl Responder {
    match create_checkout_session(&req.0, &client).await {
        Ok(res) => match res.json::<serde_json::Value>().await {
            Ok(json) => {
                if let Some(url) = json.get("url").and_then(|u| u.as_str()) {
                    HttpResponse::Ok().json(StripeResponse {
                        url: url.to_string(),
                    })
                } else {
                    eprintln!("Missing URL in Stripe response: {json:#?}");
                    HttpResponse::InternalServerError().body("Stripe response malformed")
                }
            }
            Err(e) => {
                eprintln!("Stripe JSON parse error: {e}");
                HttpResponse::InternalServerError().body("Stripe response parsing failed")
            }
        },
        Err(e) => {
            eprintln!("Stripe HTTP error: {e}");
            HttpResponse::InternalServerError().body("Stripe session creation failed")
        }
    }
}

pub async fn create_checkout_session(
    req: &CheckoutRequest,
    client: &Client,
) -> Result<reqwest::Response, reqwest::Error> {
    let stripe_secret = env::var("STRIPE_SECRET_KEY").expect("Missing STRIPE_SECRET_KEY");
    let success_url_template = env::var("STRIPE_SUCCESS_URL").expect("Missing STRIPE_SUCCESS_URL");
    let cancel_url = env::var("STRIPE_CANCEL_URL").expect("Missing STRIPE_CANCEL_URL");
    let currency = env::var("STRIPE_CURRENCY")
        .unwrap_or_else(|_| "eur".to_string())
        .to_lowercase();
    let unit_amount = env::var("STRIPE_UNIT_AMOUNT").unwrap_or_else(|_| "10".to_string());
    let product_name =
        env::var("STRIPE_PRODUCT_NAME").unwrap_or_else(|_| "Private Twilio Session".to_string());

    let success_url = success_url_template
        .replace("{room}", &req.room_name)
        .replace("{identity}", &req.identity);

    let params = [
        ("success_url", success_url),
        ("cancel_url", cancel_url),
        ("mode", "payment".to_string()),
        ("line_items[0][price_data][currency]", currency),
        ("line_items[0][price_data][unit_amount]", unit_amount),
        (
            "line_items[0][price_data][product_data][name]",
            product_name,
        ),
        ("line_items[0][quantity]", "1".to_string()),
        ("metadata[room_name]", req.room_name.clone()),
        ("metadata[identity]", req.identity.clone()),
    ];

    client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .basic_auth(stripe_secret, Some(""))
        .form(&params)
        .send()
        .await
}
