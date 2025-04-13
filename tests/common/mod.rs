use std::{sync::Arc, env};
use actix_web::{test, web, App};
use sqlx::sqlite::SqlitePoolOptions;
use reqwest::Client;

use tiny_twilio_stripe::{
    config::AppConfig,
    calendly::{start_calendly_auth, calendly_auth_callback},
    storage::{TokenStore, create_sqlite_token_store},
};

pub async fn load_test_token_store() -> impl TokenStore {
    env::set_var("DOTENV_OVERRIDE", ".env.test_calendly");
    let config = AppConfig::load().expect("Failed to load AppConfig");

    create_sqlite_token_store(
        config.database_url.as_ref().unwrap(),
        config.encryption_key.clone().unwrap().try_into().expect("Missing encryption key"),
    )
        .await
        .expect("Failed to create SqliteTokenStore")
}

pub async fn setup_test_app(test_config: AppConfig, token_store: Arc<dyn TokenStore>) -> impl actix_web::dev::Service<actix_http::Request, Response = actix_web::dev::ServiceResponse, Error = actix_web::Error> {
    let shared_config = web::Data::new(test_config.clone());
    let db_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(test_config.database_url.as_ref().unwrap())
        .await
        .expect("Failed to create pool");
    let shared_db_pool = web::Data::new(db_pool);
    let client = web::Data::new(Client::new());

    test::init_service(
        App::new()
            .app_data(shared_config)
            .app_data(shared_db_pool)
            .app_data(web::Data::from(token_store))
            .app_data(client)
            .service(start_calendly_auth)
            .service(calendly_auth_callback)
    ).await
}