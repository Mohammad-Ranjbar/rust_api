use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Serialize, Error)]
pub enum ApiError {
    #[error("Bad Request: {0}")]
    BadRequest(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Not Found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Unprocessable Entity: {0}")]
    UnprocessableEntity(String),
    
    #[error("Too Many Requests: {0}")]
    TooManyRequests(String),
    
    #[error("Internal Server Error: {0}")]
    InternalServerError(String),
    
    #[error("Service Unavailable: {0}")]
    ServiceUnavailable(String),
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        ApiError::BadRequest(msg.into())
    }
    
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        ApiError::Unauthorized(msg.into())
    }
    
    pub fn forbidden(msg: impl Into<String>) -> Self {
        ApiError::Forbidden(msg.into())
    }
    
    pub fn not_found(msg: impl Into<String>) -> Self {
        ApiError::NotFound(msg.into())
    }
    
    pub fn conflict(msg: impl Into<String>) -> Self {
        ApiError::Conflict(msg.into())
    }
    
    pub fn unprocessable_entity(msg: impl Into<String>) -> Self {
        ApiError::UnprocessableEntity(msg.into())
    }
    
    pub fn too_many_requests(msg: impl Into<String>) -> Self {
        ApiError::TooManyRequests(msg.into())
    }
    
pub fn internal(msg: Option<String>) -> Self {
    ApiError::InternalServerError(
        msg.unwrap_or_else(|| "Internal server error".to_string())
    )
}
    
    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        ApiError::ServiceUnavailable(msg.into())
    }
    
    // Convenience methods for common auth errors
    pub fn invalid_credentials() -> Self {
        ApiError::Unauthorized("Invalid credentials".to_string())
    }
    
    pub fn token_expired() -> Self {
        ApiError::Unauthorized("Token expired".to_string())
    }
    
    pub fn invalid_token() -> Self {
        ApiError::Unauthorized("Invalid token".to_string())
    }
    
    pub fn missing_auth_header() -> Self {
        ApiError::Unauthorized("Missing authorization header".to_string())
    }
    
    pub fn user_exists() -> Self {
        ApiError::Conflict("User already exists".to_string())
    }
    
    pub fn device_mismatch() -> Self {
        ApiError::Unauthorized("Device mismatch".to_string())
    }
    
    pub fn rate_limited() -> Self {
        ApiError::TooManyRequests("Rate limit exceeded".to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            ApiError::UnprocessableEntity(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            ApiError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            ApiError::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
        };

        // Log the error for internal server errors
        if matches!(self, ApiError::InternalServerError(_)) {
            tracing::error!("Internal server error: {}", message);
        }

        let body = serde_json::json!({
            "error": {
                "code": status.as_u16(),
                "message": message,
                "type": match self {
                    ApiError::BadRequest(_) => "bad_request",
                    ApiError::Unauthorized(_) => "unauthorized",
                    ApiError::Forbidden(_) => "forbidden",
                    ApiError::NotFound(_) => "not_found",
                    ApiError::Conflict(_) => "conflict",
                    ApiError::UnprocessableEntity(_) => "unprocessable_entity",
                    ApiError::TooManyRequests(_) => "too_many_requests",
                    ApiError::InternalServerError(_) => "internal_server_error",
                    ApiError::ServiceUnavailable(_) => "service_unavailable",
                }
            }
        });
        
        (status, axum::Json(body)).into_response()
    }
}

// Implement From for common error types
impl From<sea_orm::DbErr> for ApiError {
    fn from(err: sea_orm::DbErr) -> Self {
        tracing::error!("Database error: {:?}", err);
        match err {
            sea_orm::DbErr::RecordNotFound(msg) => ApiError::NotFound(msg),
            sea_orm::DbErr::Exec(err) if err.contains("unique constraint") => {
                ApiError::Conflict("Record already exists".to_string())
            }
            sea_orm::DbErr::Exec(err) if err.contains("foreign key constraint") => {
                ApiError::BadRequest("Invalid reference".to_string())
            }
            _ => ApiError::internal(None),
        }
    }
}

impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => ApiError::token_expired(),
            jsonwebtoken::errors::ErrorKind::InvalidToken => ApiError::invalid_token(),
            _ => ApiError::invalid_token(),
        }
    }
}

impl From<bcrypt::BcryptError> for ApiError {
    fn from(err: bcrypt::BcryptError) -> Self {
        tracing::error!("Bcrypt error: {:?}", err);
        ApiError::internal(None)
    }
}

impl From<validator::ValidationErrors> for ApiError {
    fn from(err: validator::ValidationErrors) -> Self {
        let errors: Vec<String> = err
            .field_errors()
            .iter()
            .map(|(field, errors)| {
                let error_messages: Vec<String> = errors
                    .iter()
                    .map(|e| {
                        e.message
                            .as_ref()
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| e.code.to_string())
                    })
                    .collect();
                format!("{}: {}", field, error_messages.join(", "))
            })
            .collect();
        
        ApiError::UnprocessableEntity(errors.join("; "))
    }
}

impl From<uuid::Error> for ApiError {
    fn from(err: uuid::Error) -> Self {
        tracing::error!("UUID error: {:?}", err);
        ApiError::internal(None)
    }
}

impl From<std::num::ParseIntError> for ApiError {
    fn from(err: std::num::ParseIntError) -> Self {
        tracing::error!("Parse int error: {:?}", err);
        ApiError::BadRequest("Invalid integer format".to_string())
    }
}

// For async operations
impl From<tokio::task::JoinError> for ApiError {
    fn from(err: tokio::task::JoinError) -> Self {
        tracing::error!("Join error: {:?}", err);
        ApiError::internal(None)
    }
}


impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!("Anyhow error: {:?}", err);
        ApiError::internal(None)
    }
}