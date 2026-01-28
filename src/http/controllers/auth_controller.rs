use crate::app_state::AppState;
use crate::entity::user;
use crate::http::errors::api_error::ApiError;
use crate::http::requests::auth_request::LoginRequest;
use crate::http::responses::auth_response::LoginResponse;
use crate::http::responses::user_response::UserResponse;
use axum::{Json, extract::State};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use validator::Validate;
use axum::extract::Extension;
use crate::entity::refresh_token;
use sea_orm::{ActiveModelTrait, Set};
use chrono::{Utc, Duration};


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
    let refresh_active = refresh_token::ActiveModel {
        token: Set(refresh_token_value.clone()),
        user_id: Set(user_model.id),
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