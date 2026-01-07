use axum::{
    extract::State,
    middleware::Next,
    http::{Request, header},
    response::Response,
    body::Body,
};
use crate::{AppState, http::errors::api_error::ApiError};

pub async fn auth_middleware(
    State(state): State<AppState>, // ← state از Router گرفته می‌شود
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(ApiError::unauthorized)?;

    let user_id = state
        .auth_service
        .decode_token(token)
        .map_err(|_| ApiError::unauthorized())?;

    req.extensions_mut().insert(user_id);

    Ok(next.run(req).await)
}
