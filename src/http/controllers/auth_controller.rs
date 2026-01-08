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

    let db = &state.db;

    let user_model = user::Entity::find()
        .filter(user::Column::Mobile.eq(payload.mobile))
        .one(db)
        .await
        .map_err(|err| {
            tracing::error!("DB error: {:?}", err);
            ApiError::internal(None)
        })?
        .ok_or_else(ApiError::unauthorized)?;

    let is_valid = state
        .auth_service
        .verify_password(&payload.password, &user_model.password_hash)
        .map_err(|err| {
            tracing::error!("Password verify error: {:?}", err);
            ApiError::internal(None)
        })?;

    if !is_valid {
        return Err(ApiError::unauthorized());
    }

    let token = state
        .auth_service
        .create_token(user_model.id)
        .map_err(|err| {
            tracing::error!("JWT encode error: {:?}", err);
            ApiError::internal(None)
        })?;

    Ok(Json(LoginResponse {
        token,
        user: user_model.into(),
    }))
}
