#![cfg(feature = "calendly")] // Adjust cfg based on all features using this: #![cfg(any(feature = "calendly", ...))]
// --- File: src/utils/sqlx_helper.rs ---

use futures::future::BoxFuture;
use futures::FutureExt;
#[allow(unused_imports)]
use sqlx::{sqlite::SqliteQueryResult, Row, SqlitePool, sqlite::SqlitePoolOptions};
// Removed async_trait import as it's not needed for native async fn in trait
// use async_trait::async_trait;
use crate::storage::{StorageError, StoredTokenRecord, TokenStore}; // Import trait and related types

// Structure holding the pool and implementing the trait
#[derive(Clone, Debug)] // Added Debug
pub struct SqliteTokenStore {
    pool: SqlitePool,
}

// Public function to create the store instance (includes pool creation)
pub async fn create_sqlite_token_store(database_url: &str) -> Result<SqliteTokenStore, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5) // Example pool size
        .connect(database_url)
        .await?;

    // Optional: Run migrations here if desired and if using sqlx-cli
    // sqlx::migrate!("./migrations").run(&pool).await?;
    // println!("✅ Database migrations ran (if any pending).");

    Ok(SqliteTokenStore { pool })
}

// Implement the TokenStore trait for our SQLite implementation
// No #[async_trait] needed if using Rust 1.75+
impl TokenStore for SqliteTokenStore {
    fn save_token<'a>(
        &'a self,
        user_id: &'a str,
        service: &'a str,
        encrypted_access_token: &'a [u8],
        encrypted_refresh_token: Option<&'a [u8]>,
        expires_at: Option<i64>,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        async move {
            let result = sqlx::query!(
                r#"
                INSERT INTO oauth_tokens (
                    user_id,
                    service,
                    access_token_encrypted,
                    refresh_token_encrypted,
                    expires_at
                )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(user_id, service) DO UPDATE SET
                    access_token_encrypted = excluded.access_token_encrypted,
                    refresh_token_encrypted = excluded.refresh_token_encrypted,
                    expires_at = excluded.expires_at;
                "#,
                user_id,
                service,
                encrypted_access_token,
                encrypted_refresh_token,
                expires_at
            )
                .execute(&self.pool)
                .await;

            match result {
                Ok(_) => Ok(()),
                Err(e) => {
                    eprintln!(
                        "DB Error saving token for user '{}', service '{}': {}",
                        user_id, service, e
                    );
                    Err(StorageError::Database(e))
                }
            }
        }
            .boxed()
    }

    fn get_token<'a>(
        &'a self,
        user_id: &'a str,
        service: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredTokenRecord>, StorageError>> {
        async move {
            let rec = sqlx::query_as!(
                StoredTokenRecord,
                r#"
                SELECT
                    access_token_encrypted,
                    refresh_token_encrypted,
                    expires_at
                FROM oauth_tokens
                WHERE user_id = ? AND service = ?
                "#,
                user_id,
                service
            )
                .fetch_optional(&self.pool)
                .await?;

            Ok(rec)
        }
            .boxed()
    }

    fn encryption_key(&self) -> &[u8] {
        // You need to define where the key comes from; for now, placeholder
        unimplemented!("You must provide the encryption key source, e.g., from config or injected secret")
    }
}
