use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use sea_orm::{
    ActiveModelTrait, Set, EntityTrait, QueryFilter, ColumnTrait, 
    DatabaseConnection,
    prelude::Expr,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use bcrypt::{hash, verify, DEFAULT_COST};

use crate::{
    entity::{refresh_token, user},
    http::errors::api_error::ApiError,
};

#[derive(Debug, Clone)]
pub struct AuthService {
    pub jwt_secret: String,
    pub jwt_expiry_minutes: i64,
    pub refresh_token_expiry_days: i64,
}

impl AuthService {
    pub fn new(jwt_secret: String, jwt_expiry_minutes: i64, refresh_token_expiry_days: i64) -> Self {
        Self {
            jwt_secret,
            jwt_expiry_minutes,
            refresh_token_expiry_days,
        }
    }

    /// Create JWT access token
    pub fn create_token(&self, user_id: i32) -> Result<String, ApiError> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::minutes(self.jwt_expiry_minutes))
            .ok_or_else(|| {
                tracing::error!("Failed to calculate token expiration");
                ApiError::internal(None)
            })?
            .timestamp();

        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration as usize,
            iat: Utc::now().timestamp() as usize,
            iss: "your-app".to_string(),
            aud: "your-app-users".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|err| {
            tracing::error!("Failed to encode JWT token: {:?}", err);
            ApiError::internal(None)
        })
    }

    /// Verify JWT access token
    pub fn verify_token(&self, token: &str) -> Result<Claims, ApiError> {
        let mut validation = Validation::default();
        validation.set_audience(&["your-app-users"]);
        validation.set_issuer(&["your-app"]);

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|err| {
            match err.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    ApiError::Unauthorized("Token expired".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    ApiError::Unauthorized("Invalid token".to_string())
                }
                _ => {
                    tracing::error!("JWT verification error: {:?}", err);
                    ApiError::Unauthorized("Token verification failed".to_string())
                }
            }
        })?;

        Ok(token_data.claims)
    }

    /// Create refresh token
    pub async fn create_refresh_token(
        &self,
        db: &DatabaseConnection,
        user_id: i32,
        device_info: Option<DeviceInfo>,
    ) -> Result<String, ApiError> {
        // Check if user exists
        let user_exists = user::Entity::find_by_id(user_id)
            .one(db)
            .await
            .map_err(|err| {
                tracing::error!("Database error checking user: {:?}", err);
                ApiError::internal(None)
            })?
            .is_some();

        if !user_exists {
            return Err(ApiError::NotFound("User not found".to_string()));
        }

        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now()
            .checked_add_signed(Duration::days(self.refresh_token_expiry_days))
            .ok_or_else(|| {
                tracing::error!("Failed to calculate refresh token expiration");
                ApiError::internal(None)
            })?
            .naive_utc();

let mut refresh_token = refresh_token::ActiveModel {
    token: Set(token.clone()),
    user_id: Set(user_id),
    expires_at: Set(Utc::now() + Duration::days(self.refresh_token_expiry_days)), 
    revoked: Set(false),
    created_at: Set(Utc::now()), 
    updated_at: Set(Utc::now()), 
    ..Default::default()
};

        // Add optional device info
        if let Some(info) = device_info {
            refresh_token.device_id = Set(info.device_id);
            refresh_token.ip_address = Set(info.ip_address);
            refresh_token.user_agent = Set(info.user_agent);
        }

     refresh_token.insert(db).await.map_err(|err| {
    // Convert DbErr to string and check for unique constraint
    let err_str = err.to_string();
    
    if err_str.to_lowercase().contains("unique constraint") 
        || err_str.to_lowercase().contains("duplicate entry")
        || err_str.to_lowercase().contains("unique violation")
        || err_str.contains("23505") { // PostgreSQL unique violation error code
        
        ApiError::Conflict("Token already exists".to_string())
    } else {
        tracing::error!("Failed to create refresh token: {:?}", err);
        ApiError::internal(None)
    }
})?;

        Ok(token)
    }

    /// Verify refresh token
    pub async fn verify_refresh_token(
        &self,
        db: &DatabaseConnection,
        token: &str,
        device_id: Option<String>,
    ) -> Result<refresh_token::Model, ApiError> {
        let refresh_token = refresh_token::Entity::find()
            .filter(refresh_token::Column::Token.eq(token))
            .one(db)
            .await
            .map_err(|err| {
                tracing::error!("Database error finding refresh token: {:?}", err);
                ApiError::internal(None)
            })?
            .ok_or_else(|| ApiError::Unauthorized("Invalid refresh token".to_string()))?;

        // Check if token is expired
        let now = Utc::now();
        if refresh_token.expires_at < now {
            return Err(ApiError::Unauthorized("Refresh token expired".to_string()));
        }

        // Check if token is revoked
        if refresh_token.revoked {
            return Err(ApiError::Unauthorized("Refresh token revoked".to_string()));
        }

        // Verify device ID matches (if provided)
        if let Some(device_id) = device_id {
            if let Some(stored_device_id) = &refresh_token.device_id {
                if stored_device_id != &device_id {
                    tracing::warn!(
                        "Device mismatch for refresh token: stored={:?}, provided={}",
                        stored_device_id,
                        device_id
                    );
                    return Err(ApiError::Unauthorized("Device mismatch".to_string()));
                }
            }
        }

        Ok(refresh_token)
    }

    /// Revoke a specific refresh token
    pub async fn revoke_refresh_token(
        &self,
        db: &DatabaseConnection,
        token: &str,
    ) -> Result<(), ApiError> {
        let refresh_token = refresh_token::Entity::find()
            .filter(refresh_token::Column::Token.eq(token))
            .one(db)
            .await
            .map_err(|err| {
                tracing::error!("Database error finding refresh token: {:?}", err);
                ApiError::internal(None)
            })?
            .ok_or_else(|| ApiError::NotFound("Refresh token not found".to_string()))?;

        let mut token_active: refresh_token::ActiveModel = refresh_token.into();
        token_active.revoked = Set(true);
        token_active.updated_at = Set(Utc::now());

        token_active.update(db).await.map_err(|err| {
            tracing::error!("Failed to revoke refresh token: {:?}", err);
            ApiError::internal(None)
        })?;

        Ok(())
    }

    /// Revoke all refresh tokens for a user
    pub async fn revoke_all_user_refresh_tokens(
        &self,
        db: &DatabaseConnection,
        user_id: i32,
    ) -> Result<u64, ApiError> {
        let result = refresh_token::Entity::update_many()
            .col_expr(refresh_token::Column::Revoked, Expr::value(true))
            .col_expr(
                refresh_token::Column::UpdatedAt,
                Expr::value(Utc::now().naive_utc()),
            )
            .filter(refresh_token::Column::UserId.eq(user_id))
            .filter(refresh_token::Column::Revoked.eq(false))
            .exec(db)
            .await
            .map_err(|err| {
                tracing::error!("Failed to revoke user refresh tokens: {:?}", err);
                ApiError::internal(None)
            })?;

        Ok(result.rows_affected)
    }

    /// Hash password using bcrypt
    pub fn hash_password(password: &str) -> Result<String, ApiError> {
        hash(password, DEFAULT_COST).map_err(|err| {
            tracing::error!("Failed to hash password: {:?}", err);
            ApiError::internal(None)
        })
    }

    /// Verify password against hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, ApiError> {
        verify(password, hash).map_err(|err| {
            tracing::error!("Failed to verify password: {:?}", err);
            ApiError::internal(None)
        })
    }

    /// Generate token pair (access + refresh)
    pub async fn generate_token_pair(
        &self,
        db: &DatabaseConnection,
        user_id: i32,
        device_info: Option<DeviceInfo>,
    ) -> Result<(String, String), ApiError> {
        let access_token = self.create_token(user_id)?;
        let refresh_token = self.create_refresh_token(db, user_id, device_info).await?;

        Ok((access_token, refresh_token))
    }

    /// Clean up expired refresh tokens
    pub async fn cleanup_expired_tokens(
        &self,
        db: &DatabaseConnection,
    ) -> Result<u64, ApiError> {
        let now = Utc::now().naive_utc();
        
        let result = refresh_token::Entity::delete_many()
            .filter(refresh_token::Column::ExpiresAt.lt(now))
            .filter(refresh_token::Column::Revoked.eq(false))
            .exec(db)
            .await
            .map_err(|err| {
                tracing::error!("Failed to cleanup expired tokens: {:?}", err);
                ApiError::internal(None)
            })?;

        tracing::info!("Cleaned up {} expired refresh tokens", result.rows_affected);
        Ok(result.rows_affected)
    }

    /// Get active refresh tokens for user
    pub async fn get_user_refresh_tokens(
        &self,
        db: &DatabaseConnection,
        user_id: i32,
        include_revoked: bool,
    ) -> Result<Vec<refresh_token::Model>, ApiError> {
        let mut query = refresh_token::Entity::find()
            .filter(refresh_token::Column::UserId.eq(user_id));

        if !include_revoked {
            query = query.filter(refresh_token::Column::Revoked.eq(false));
        }

        query
            .all(db)
            .await
            .map_err(|err| {
                tracing::error!("Failed to get user refresh tokens: {:?}", err);
                ApiError::internal(None)
            })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // Subject (user ID)
    pub exp: usize,       // Expiration time
    pub iat: usize,       // Issued at
    pub iss: String,      // Issuer
    pub aud: String,      // Audience
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl DeviceInfo {
    pub fn new(
        device_id: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        Self {
            device_id,
            ip_address,
            user_agent,
        }
    }
}

/// Middleware extractor for authentication
pub struct AuthMiddleware {
    pub user_id: i32,
    pub claims: Claims,
}

impl AuthMiddleware {
    pub async fn from_request(
        req: &axum::extract::Request,
        auth_service: &AuthService,
    ) -> Result<Self, ApiError> {
        let token = req.headers()
            .get("Authorization")
            .and_then(|header| header.to_str().ok())
            .and_then(|header| {
                if header.starts_with("Bearer ") {
                    Some(header[7..].to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| ApiError::Unauthorized("Missing authorization header".to_string()))?;

        let claims = auth_service.verify_token(&token)?;
        
        let user_id = claims.sub.parse::<i32>()
            .map_err(|_| ApiError::Unauthorized("Invalid user ID in token".to_string()))?;

        Ok(Self { user_id, claims })
    }
}