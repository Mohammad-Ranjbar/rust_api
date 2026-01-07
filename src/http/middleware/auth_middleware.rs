use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::sync::OnceLock;

// 👈 یک بار global JWT secret
static JWT_SECRET: OnceLock<String> = OnceLock::new();

pub fn set_jwt_secret(secret: String) {
    JWT_SECRET.set(secret).expect("JWT_SECRET already set");
}

pub async fn auth_middleware(
    mut req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let token = match req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(t) => t,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    // decode JWT
    let secret = JWT_SECRET.get().expect("JWT_SECRET not set");

    let user_id = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    ) {
        Ok(data) => data.claims.sub,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    req.extensions_mut().insert(user_id);

    next.run(req).await
}

use serde::{Serialize, Deserialize};
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i32,
    exp: usize,
}
