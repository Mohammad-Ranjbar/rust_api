use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use chrono::Utc;
use sea_orm::{EntityTrait, ColumnTrait, QueryFilter};
use crate::http::types::claims::Claims;
use crate::app_state::AppState;
use crate::entity::refresh_token;
use std::sync::OnceLock;

static JWT_SECRET: OnceLock<String> = OnceLock::new();

pub fn set_jwt_secret(secret: String) {
    JWT_SECRET.set(secret).expect("JWT_SECRET already set");
}

pub async fn auth_middleware(
    mut req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
   
    let state = match req.extensions().get::<AppState>() {
        Some(s) => s,
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let token = match req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(t) => t,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let secret = JWT_SECRET.get().expect("JWT_SECRET not set");


    let user_id = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    ) {
        Ok(data) => data.claims.sub,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let now = Utc::now();
    let active_tokens = match refresh_token::Entity::find()
        .filter(refresh_token::Column::UserId.eq(user_id))
        .filter(
            refresh_token::Column::Revoked.eq(false)
                .and(refresh_token::Column::ExpiresAt.gt(now))
        )
        .all(&state.db)
        .await
    {
        Ok(tokens) => tokens,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if active_tokens.is_empty() {
        return StatusCode::UNAUTHORIZED.into_response();
    }


    req.extensions_mut().insert(user_id);

    next.run(req).await
}
