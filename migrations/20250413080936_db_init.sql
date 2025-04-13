-- Migration script: Create the oauth_tokens table

-- Create the table only if it doesn't already exist
CREATE TABLE IF NOT EXISTS oauth_tokens (
    -- Identifier for the user who authorized the service (e.g., internal user ID, email)
    -- Part of the composite primary key.
                                            user_id TEXT NOT NULL,

    -- Identifier for the service the token belongs to (e.g., 'calendly', 'google', etc.)
    -- Part of the composite primary key.
                                            service TEXT NOT NULL,

    -- The encrypted OAuth access token, stored as raw bytes. Cannot be NULL.
                                            access_token_encrypted BLOB NOT NULL,

    -- The encrypted OAuth refresh token, stored as raw bytes.
    -- This can be NULL if the service doesn't provide a refresh token.
                                            refresh_token_encrypted BLOB, -- NULLable

    -- The Unix timestamp (seconds since epoch) when the access token expires.
    -- This can be NULL if the access token does not expire or expiry is unknown.
                                            expires_at INTEGER,           -- NULLable

    -- Define a composite primary key to ensure only one set of tokens
    -- per user per service. This also facilitates INSERT OR REPLACE/ON CONFLICT logic.
                                            PRIMARY KEY (user_id, service)
    );

-- Optional: Add an index for potentially faster lookups if you query frequently by user_id and service.
-- The PRIMARY KEY implicitly creates a unique index, but an explicit index might be useful depending on query patterns.
-- CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_service ON oauth_tokens (user_id, service);

