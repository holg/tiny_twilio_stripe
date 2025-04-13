// --- File: src/storage.rs ---

use thiserror::Error;
use futures::future::BoxFuture;
use crate::utils::crypto::{encrypt, decrypt}; // Add this to top if needed

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database query failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Token not found for user {user_id} and service {service}")]
    NotFound { user_id: String, service: String },
    // Keep encryption error if needed for decryption results, or handle elsewhere
    // #[error("Encryption/Decryption failed: {0}")]
    // Encryption(String),
}

// Define a structure to hold the raw encrypted data retrieved from storage
#[derive(Debug)]
pub struct StoredTokenRecord {
    pub access_token_encrypted: Vec<u8>,
    pub refresh_token_encrypted: Option<Vec<u8>>,
    pub expires_at: Option<i64>,
}

// The trait defining token storage operations
// Methods now handle encrypted byte slices/vectors
pub trait TokenStore: Send + Sync {
    fn save_token<'a>(
        &'a self,
        user_id: &'a str,
        service: &'a str,
        encrypted_access_token: &'a [u8],
        encrypted_refresh_token: Option<&'a [u8]>,
        expires_at: Option<i64>,
    ) -> BoxFuture<'a, Result<(), StorageError>>;

    fn get_token<'a>(
        &'a self,
        user_id: &'a str,
        service: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredTokenRecord>, StorageError>>;

    fn encryption_key(&self) -> &[u8];

    fn save_token_encrypted<'a>(
        &'a self,
        user_id: &'a str,
        service: &'a str,
        access_token: &'a str,
        refresh_token: Option<&'a str>,
        expires_at: Option<i64>,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        let key = self.encryption_key().to_owned();
        let access_token = access_token.to_owned();
        let refresh_token = refresh_token.map(str::to_owned);
        Box::pin(async move {
            let enc_access = encrypt(&key, access_token.as_bytes())
                .map_err(|e| StorageError::Database(sqlx::Error::Protocol(e.to_string().into())))?;
            let enc_refresh = match refresh_token {
                Some(rt) => Some(encrypt(&key, rt.as_bytes())
                    .map_err(|e| StorageError::Database(sqlx::Error::Protocol(e.to_string().into())))?),
                None => None,
            };
            self.save_token(user_id, service, &enc_access, enc_refresh.as_deref(), expires_at).await
        })
    }

    fn get_token_decrypted<'a>(
        &'a self,
        user_id: &'a str,
        service: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, Option<String>, Option<i64>)>, StorageError>> {
        let key = self.encryption_key().to_owned();
        Box::pin(async move {
            match self.get_token(user_id, service).await? {
                Some(rec) => {
                    let access = decrypt(&key, &rec.access_token_encrypted)
                        .map_err(|e| StorageError::Database(sqlx::Error::Protocol(e.to_string().into())))?;
                    let refresh = match rec.refresh_token_encrypted {
                        Some(rt) => Some(decrypt(&key, &rt)
                            .map_err(|e| StorageError::Database(sqlx::Error::Protocol(e.to_string().into())))?),
                        None => None,
                    };
                    Ok(Some((
                        String::from_utf8(access).unwrap_or_default(),
                        refresh.map(|r| String::from_utf8(r).unwrap_or_default()),
                        rec.expires_at
                    )))
                }
                None => Ok(None),
            }
        })
    }
}

// Add the SqliteTokenStore struct definition with the new field
pub struct SqliteTokenStore {
    pool: sqlx::SqlitePool,
    encryption_key: Vec<u8>,
}

// Update the create_sqlite_token_store function signature
pub async fn create_sqlite_token_store(database_url: &str, encryption_key: Vec<u8>) -> Result<SqliteTokenStore, sqlx::Error> {
    let pool = sqlx::SqlitePool::connect(database_url).await?;
    Ok(SqliteTokenStore { pool, encryption_key })
}

// Implement the encryption_key method for SqliteTokenStore
impl TokenStore for SqliteTokenStore {
    fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }
    fn save_token<'a>(&'a self, user_id: &'a str, service: &'a str,
                      encrypted_access_token: &'a [u8], encrypted_refresh_token: Option<&'a [u8]>,
                      expires_at: Option<i64>) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            sqlx::query!(
                r#"
                INSERT INTO oauth_tokens (user_id, service, access_token_encrypted, refresh_token_encrypted, expires_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(user_id, service) DO UPDATE SET
                    access_token_encrypted = excluded.access_token_encrypted,
                    refresh_token_encrypted = excluded.refresh_token_encrypted,
                    expires_at = excluded.expires_at
                "#,
                user_id,
                service,
                encrypted_access_token,
                encrypted_refresh_token,
                expires_at
            )
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }
    fn get_token<'a>(&'a self, user_id: &'a str, service: &'a str) -> BoxFuture<'a, Result<Option<StoredTokenRecord>, StorageError>> {
        Box::pin(async move {
            let rec = sqlx::query!(
                r#"
                SELECT access_token_encrypted, refresh_token_encrypted, expires_at
                FROM oauth_tokens
                WHERE user_id = ? AND service = ?
                "#,
                user_id,
                service
            )
            .fetch_optional(&self.pool)
            .await?;

            Ok(rec.map(|r| StoredTokenRecord {
                access_token_encrypted: r.access_token_encrypted,
                refresh_token_encrypted: r.refresh_token_encrypted,
                expires_at: r.expires_at,
            }))
        })
    }
}
