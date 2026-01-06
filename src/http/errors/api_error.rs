use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(Option<String>),
    Unauthorized(Option<String>),
    Forbidden(Option<String>),
    NotFound(Option<String>),
    UnprocessableEntity(Option<String>),
    InternalServerError(Option<String>),
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
}

impl ApiError {
    // پیام پیش‌فرض هر نوع خطا
    fn default_message(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "Bad request",
            ApiError::Unauthorized(_) => "Unauthorized",
            ApiError::Forbidden(_) => "Forbidden",
            ApiError::NotFound(_) => "User not available",
            ApiError::UnprocessableEntity(_) => "Invalid input data",
            ApiError::InternalServerError(_) => "Internal server error",
        }
    }

    // پیام قابل ارسال در JSON
    pub fn message(&self) -> String {
        match self {
            ApiError::BadRequest(msg)
            | ApiError::Unauthorized(msg)
            | ApiError::Forbidden(msg)
            | ApiError::NotFound(msg)
            | ApiError::UnprocessableEntity(msg)
            | ApiError::InternalServerError(msg) => {
                msg.clone().unwrap_or_else(|| self.default_message().to_string())
            }
        }
    }

    // ===== Constructors برای راحتی =====
    pub fn bad_request() -> Self { Self::BadRequest(None) }
    pub fn bad_request_msg(msg: impl Into<String>) -> Self { Self::BadRequest(Some(msg.into())) }

    pub fn unauthorized() -> Self { Self::Unauthorized(None) }
    pub fn unauthorized_msg(msg: impl Into<String>) -> Self { Self::Unauthorized(Some(msg.into())) }

    pub fn forbidden() -> Self { Self::Forbidden(None) }
    pub fn forbidden_msg(msg: impl Into<String>) -> Self { Self::Forbidden(Some(msg.into())) }

    pub fn not_found() -> Self { Self::NotFound(None) }
    pub fn not_found_msg(msg: impl Into<String>) -> Self { Self::NotFound(Some(msg.into())) }

    pub fn unprocessable() -> Self { Self::UnprocessableEntity(None) }
    pub fn unprocessable_msg(msg: impl Into<String>) -> Self { Self::UnprocessableEntity(Some(msg.into())) }

    pub fn internal(msg: Option<String>) -> Self { Self::InternalServerError(msg) }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(ErrorResponse { message: self.message() });

        (status, body).into_response()
    }
}
