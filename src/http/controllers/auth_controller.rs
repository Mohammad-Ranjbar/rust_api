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
use axum::extract::ConnectInfo;
use std::net::SocketAddr;
use sea_orm::sea_query::Expr;
use tracing::error;


pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
        ConnectInfo(addr): ConnectInfo<SocketAddr>, 
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let user_model = user::Entity::find()
        .filter(user::Column::Mobile.eq(payload.mobile.clone()))
        .one(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(|| ApiError::unauthorized_msg("User not found"))?;

    let is_valid = state.auth_service.verify_password(&payload.password, &user_model.password_hash);
    if !is_valid {
        return Err(ApiError::unauthorized_msg("Invalid password"));
    }

    let tokens = state.auth_service
        .issue_tokens(user_model.id, &headers, &addr) 
        .map_err(|_| ApiError::internal(None))?;

    let refresh_hash = state.auth_service.hash_refresh_token(&tokens.refresh_token);
    let refresh_model = refresh_token::ActiveModel {
        user_id: Set(user_model.id),
        token_hash: Set(refresh_hash),
        device_id: Set(tokens.session.device_id.clone()),
        ip_address: Set(tokens.session.ip_address.clone()),
        user_agent: Set(tokens.session.user_agent.clone()),
        expires_at: Set(Utc::now() + chrono::Duration::days(30)), 
        ..Default::default()
    };
    refresh_model.insert(&state.db).await.map_err(|_| ApiError::internal(None))?;

    Ok(Json(LoginResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        user: user_model.into(), 
    }))
}


pub async fn profile(
    State(state): State<AppState>,
    Extension(user_id): Extension<i32>,
) -> Result<Json<user::Model>, ApiError> {
    // بررسی مدل کاربر از DB
    let user_model = match user::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
    {
        Ok(Some(model)) => model, // کاربر پیدا شد
        Ok(None) => {
            error!("User with id {} not found", user_id);
            return Err(ApiError::not_found());
        }
        Err(e) => {
            error!("Database query failed for user_id {}: {:?}", user_id, e);
            return Err(ApiError::internal(Some(format!(
                "DB error: {}",
                e
            ))));
        }
    };


    match serde_json::to_value(&user_model) {
        Ok(_) => Ok(Json(user_model)),
        Err(e) => {
            error!("Failed to serialize user model: {:?}", e);
            Err(ApiError::internal(Some(format!(
                "Serialization error: {}",
                e
            ))))
        }
    }
}



pub async fn refresh_token(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<RefreshTokenResponse>, ApiError> {
    let now = Utc::now();

    let refresh_hash = state.auth_service.hash_refresh_token(&payload.refresh_token);

    let token_model = refresh_token::Entity::find()
        .filter(refresh_token::Column::TokenHash.eq(refresh_hash.clone()))
        .one(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(|| ApiError::unauthorized_msg("Invalid refresh token"))?;


    if token_model.revoked || token_model.expires_at < now {
        refresh_token::Entity::update_many()
            .col_expr(refresh_token::Column::Revoked, Expr::value(true))
            .filter(refresh_token::Column::UserId.eq(token_model.user_id))
            .exec(&state.db)
            .await
            .map_err(|_| ApiError::internal(None))?;

        return Err(ApiError::unauthorized_msg("Refresh token revoked or expired. Please login again."));
    }

    let mut active: refresh_token::ActiveModel = token_model.clone().into();
    active.revoked = Set(true);
    active.update(&state.db).await.map_err(|_| ApiError::internal(None))?;

    let tokens = state.auth_service
        .issue_tokens(token_model.user_id, &headers, &addr)
        .map_err(|_| ApiError::internal(None))?;

    let refresh_hash = state.auth_service.hash_refresh_token(&tokens.refresh_token);
    let refresh_model = refresh_token::ActiveModel {
        user_id: Set(token_model.user_id),
        token_hash: Set(refresh_hash),
        device_id: Set(tokens.session.device_id.clone()),
        ip_address: Set(Some(addr.ip().to_string())),
        user_agent: Set(tokens.session.user_agent.clone()),
        expires_at: Set(Utc::now() + chrono::Duration::days(30)),
        ..Default::default()
    };
    refresh_model.insert(&state.db).await.map_err(|_| ApiError::internal(None))?;

    Ok(Json(RefreshTokenResponse {
        access_token: tokens.access_token
    }))
}
