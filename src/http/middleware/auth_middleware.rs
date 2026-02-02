use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::sync::OnceLock;
use tracing::{info, error};

use crate::http::types::claims::Claims;

static JWT_SECRET: OnceLock<String> = OnceLock::new();

pub fn set_jwt_secret(secret: String) {
    JWT_SECRET.set(secret).expect("JWT_SECRET already set");
}

pub async fn auth_middleware(
    mut req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    info!("auth middleware called");

    // 1️⃣ Authorization header
    let token = match req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(t) => t,
        None => {
            error!("Authorization header missing");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    // 2️⃣ JWT secret
    let secret = match JWT_SECRET.get() {
        Some(s) => s,
        None => {
            error!("JWT_SECRET not set");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // 3️⃣ Decode JWT
    let claims = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data.claims,
        Err(e) => {
            error!("JWT decode failed: {:?}", e);
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let user_id = claims.sub;
    info!("authenticated user_id={}", user_id);

    // 4️⃣ inject user_id for handlers
    req.extensions_mut().insert(user_id);

    // 5️⃣ continue
    next.run(req).await
}
