use axum::response::{IntoResponse, Response};
use axum::http::StatusCode;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum ApiError {
    NotFound(String),
    UnprocessableEntity(String),
    InternalServerError(Option<String>),
}
impl ApiError {
    pub fn internal(msg: Option<String>) -> Self {
        ApiError::InternalServerError(msg)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::UnprocessableEntity(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            ApiError::InternalServerError(msg) => {
                let text = msg.unwrap_or("Internal server error".to_string());
                (StatusCode::INTERNAL_SERVER_ERROR,text) },
        };

        let body = serde_json::json!({ "message": message });
        (status, axum::Json(body)).into_response()
    }
}
