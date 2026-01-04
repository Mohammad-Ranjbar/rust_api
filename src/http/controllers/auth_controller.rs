use axum::{
    extract::State,
    Json,
    response::{IntoResponse, Response},
};
use sea_orm::{ActiveModelTrait, Set, EntityTrait, ColumnTrait, QueryFilter};
use validator::Validate;

use crate::db::Db;
use crate::entity::user as user_entity;
use crate::http::requests::auth_request::{LoginRequest, RegisterRequest};
use crate::http::responses::auth_response::AuthResponse;
use crate::http::errors::api_error::ApiError;
use crate::http::services::auth_service::AuthService;

pub async fn register(
    State(db): State<Db>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    payload.validate().map_err(|_| ApiError::UnprocessableEntity(
        "Invalid input data".to_string(),
    ))?;

    let password_hash = AuthService::hash_password(&payload.password)
        .map_err(|_| ApiError::internal(None))?;

    let user = user_entity::ActiveModel {
        mobile: Set(payload.mobile.clone()),
        name: Set(payload.name),
        family: Set(payload.family),
        password_hash: Set(password_hash),
        ..Default::default()
    };

    let user = user.insert(&db).await.map_err(|err| {
        tracing::error!("db error: {:?}", err);
        ApiError::internal(None)
    })?;

 
    let token = AuthService::create_token(user.id)
        .map_err(|_| ApiError::internal(None))?;

    Ok(Json(AuthResponse {
        token,
        user_id: user.id,
        mobile: user.mobile,
    }))
}

pub async fn login(
    State(db): State<Db>,
    Json(payload): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    payload.validate().map_err(|_| ApiError::UnprocessableEntity(
        "Invalid input data".to_string(),
    ))?;

    let user = user_entity::Entity::find()
        .filter(user_entity::Column::Mobile.eq(&payload.mobile))
        .one(&db)
        .await
        .map_err(|_| ApiError::internal(None))?;

    let user = user.ok_or_else(|| ApiError::NotFound("Invalid credentials".to_string()))?;

    // Verify Password
    let is_valid = AuthService::verify_password(&payload.password, &user.password_hash)
        .map_err(|_| ApiError::internal(None))?;

    if !is_valid {
        return Err(ApiError::NotFound("Invalid credentials".to_string()));
    }

    // Generate Token
    let token = AuthService::create_token(user.id)
        .map_err(|_| ApiError::internal(None))?;

    Ok(Json(AuthResponse {
        token,
        user_id: user.id,
        mobile: user.mobile,
    }).into_response())
}