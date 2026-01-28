use crate::app_state::AppState;
use crate::entity::user;
use crate::http::errors::api_error::ApiError;
use crate::http::requests::auth_request::LoginRequest;
use crate::http::requests::refresh_token_request::RefreshTokenRequest;
use crate::http::responses::auth_response::LoginResponse;
use crate::http::responses::user_response::UserResponse;
use axum::{Json, extract::State};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use validator::Validate;
use axum::extract::Extension;
use crate::entity::refresh_token;
use sea_orm::{ActiveModelTrait, Set};
use chrono::{Utc, Duration};
use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use std::net::SocketAddr;


pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    payload.validate().map_err(|_| ApiError::unprocessable())?;

    // 1️⃣ پیدا کردن refresh token
    let token_model = refresh_token::Entity::find()
        .filter(refresh_token::Column::Token.eq(&payload.refresh_token))
        .filter(refresh_token::Column::Revoked.eq(false))
        .one(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(ApiError::unauthorized)?;

    // 2️⃣ بررسی انقضا
    if token_model.expires_at < Utc::now() {
        return Err(ApiError::unauthorized());
    }

    // 3️⃣ پیدا کردن کاربر
    let user_model = user::Entity::find_by_id(token_model.user_id)
        .one(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(ApiError::unauthorized)?;

    // 4️⃣ revoke کردن refresh token قبلی
    let mut old_token: refresh_token::ActiveModel = token_model.into();
    old_token.revoked = Set(true);

    old_token
        .update(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?;

    // 5️⃣ ساخت access token جدید
    let access_token = state
        .auth_service
        .create_token(user_model.id)
        .map_err(|_| ApiError::internal(None))?;

    // 6️⃣ ساخت refresh token جدید
    let new_refresh_token = state.auth_service.generate_refresh_token();

    let new_refresh_active = refresh_token::ActiveModel {
        token: Set(new_refresh_token.clone()),
        user_id: Set(user_model.id),
        expires_at: Set(
            (Utc::now() + Duration::days(30)).into()
        ),
        revoked: Set(false),
        ..Default::default()
    };

    new_refresh_active
        .insert(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token: new_refresh_token,
        user: user_model.into(),
    }))
}


pub async fn profile(
    State(state): State<AppState>,
    Extension(user_id): Extension<i32>,
) -> Result<Json<UserResponse>, ApiError> {
    let user_model = user::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(ApiError::not_found)?;

    Ok(Json(user_model.into()))
}
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    payload.validate().map_err(|_| ApiError::unprocessable())?;

    let user_model = user::Entity::find()
        .filter(user::Column::Mobile.eq(payload.mobile))
        .one(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(ApiError::unauthorized)?;

    let is_valid = state
        .auth_service
        .verify_password(&payload.password, &user_model.password_hash)
        .map_err(|_| ApiError::internal(None))?;

    if !is_valid {
        return Err(ApiError::unauthorized());
    }

    // 1️⃣ access token
    let access_token = state
        .auth_service
        .create_token(user_model.id)
        .map_err(|_| ApiError::internal(None))?;

    // 2️⃣ refresh token
    let refresh_token_value = state.auth_service.generate_refresh_token();

    // 3️⃣ ذخیره refresh token
    let issued = state
    .auth_service
    .issue_tokens(user_model.id, &headers, &addr)
    .map_err(|_| ApiError::internal(None))?;
    let refresh_active = refresh_token::ActiveModel {
        token: Set(refresh_token_value.clone()),
        user_id: Set(user_model.id),
        device_id: Set(issued.session.device_id),
        ip_address: Set(issued.session.ip_address),
        user_agent: Set(issued.session.user_agent),
        expires_at: Set(
            (Utc::now() + Duration::days(30)).into()
        ),
        revoked: Set(false),
        ..Default::default()
    };

    refresh_active
        .insert(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token: refresh_token_value,
        user: user_model.into(),
    }))
}