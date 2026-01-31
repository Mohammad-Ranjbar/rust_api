use axum::{
    extract::{State, Extension, Json},
    http::HeaderMap,
};
use chrono::Utc;
use sea_orm::{EntityTrait, ActiveModelTrait, Set, QueryFilter, ColumnTrait};
use crate::app_state::AppState;
use crate::http::errors::api_error::ApiError;
use crate::http::requests::auth_request::LoginRequest;
use crate::http::requests::refresh_token_request::RefreshTokenRequest;
use crate::http::responses::auth_response::{LoginResponse, RefreshTokenResponse};
use crate::entity::{user, refresh_token};

/// POST /login
/// POST /login
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // find user
    let user_model = user::Entity::find()
        .filter(user::Column::Mobile.eq(payload.mobile.clone()))
        .one(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(|| ApiError::unauthorized_msg("User not found"))?;

    // verify password
    let is_valid = state.auth_service.verify_password(&payload.password, &user_model.password_hash);
    if !is_valid {
        return Err(ApiError::unauthorized_msg("Invalid password"));
    }

    // issue tokens
    let tokens = state.auth_service.issue_tokens(user_model.id, &headers, &std::net::SocketAddr::from(([127,0,0,1],0)))
        .map_err(|_| ApiError::internal(None))?;

    // store refresh token hashed in DB
    let refresh_hash = state.auth_service.hash_refresh_token(&tokens.refresh_token);
    let refresh_model = refresh_token::ActiveModel {
        user_id: Set(user_model.id),
        token_hash: Set(refresh_hash),
        device_id: Set(tokens.session.device_id.clone()),
        ip_address: Set(tokens.session.ip_address.clone()),
        user_agent: Set(tokens.session.user_agent.clone()),
        expires_at: Set(Utc::now()), // adjust type to DateTime<Utc>
        ..Default::default()
    };
    refresh_model.insert(&state.db).await.map_err(|_| ApiError::internal(None))?;

    Ok(Json(LoginResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        user: user_model.into(), // convert Model -> UserResponse
    }))
}

/// POST /refresh-token
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<RefreshTokenResponse>, ApiError> {
    let refresh_hash = state.auth_service.hash_refresh_token(&payload.refresh_token);

    let token_model = refresh_token::Entity::find()
        .filter(refresh_token::Column::TokenHash.eq(refresh_hash))
        .one(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(|| ApiError::unauthorized_msg("Invalid refresh token"))?;

    let access_token = state.auth_service.create_token(token_model.user_id)
        .map_err(|_| ApiError::internal(None))?;

    Ok(Json(RefreshTokenResponse { access_token }))
}

/// GET /profile
pub async fn profile(
    State(state): State<AppState>,
    Extension(user_id): Extension<i32>,
) -> Result<Json<user::Model>, ApiError> {
    let user_model = user::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(ApiError::not_found)?;

    Ok(Json(user_model))
}
