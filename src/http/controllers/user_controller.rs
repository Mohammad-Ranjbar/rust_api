use axum::{
    extract::{State, Path, Extension},
    Json,
};
use crate::app_state::AppState;
use crate::http::errors::api_error::ApiError;
use crate::http::services::auth_service::AuthService;
use crate::entity::user;
use crate::http::requests::user_request::{CreateUserRequest, UpdateUserRequest};
use crate::http::requests::update_profile_request::UpdateProfileRequest;
use crate::http::responses::user_response::UserResponse;
use validator::Validate;
use sea_orm::{ActiveModelTrait, EntityTrait, Set,QueryOrder};

/// لیست همه کاربران
pub async fn index(
    State(state): State<AppState>,
) -> Result<Json<Vec<UserResponse>>, ApiError> {
    let models = user::Entity::find()
        .order_by_desc(user::Column::CreatedAt)
        .all(&state.db)
        .await
        .map_err(|err| {
            tracing::error!("db error: {:?}", err);
            ApiError::internal(None)
        })?;

    Ok(Json(models.into_iter().map(Into::into).collect()))
}

/// نمایش یک کاربر
pub async fn show(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<UserResponse>, ApiError> {
    let id: i32 = id.parse().map_err(|_| ApiError::unprocessable())?;
    let model = user::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|err| {
            tracing::error!("Database error: {:?}", err);
            ApiError::internal(None)
        })?
        .ok_or_else(ApiError::not_found)?;

    Ok(Json(model.into()))
}

/// ثبت کاربر جدید
pub async fn store(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    payload.validate().map_err(|_| ApiError::unprocessable())?;

    let password_hash = AuthService::hash_password(&payload.password);

    let user_active = user::ActiveModel {
        mobile: Set(payload.mobile),
        name: Set(payload.name),
        family: Set(payload.family),
        password_hash: Set(password_hash),
        ..Default::default()
    };

    let model = user_active.insert(&state.db).await.map_err(|err| {
        tracing::error!("Database insert error: {:?}", err);
        ApiError::internal(None)
    })?;

    Ok(Json(model.into()))
}

/// بروزرسانی کاربر توسط admin
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    payload.validate().map_err(|_| ApiError::unprocessable())?;

    let id: i32 = id.parse().map_err(|_| ApiError::unprocessable())?;
    let model = user::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|err| {
            tracing::error!("Database error: {:?}", err);
            ApiError::internal(None)
        })?
        .ok_or_else(ApiError::not_found)?;

    let mut active: user::ActiveModel = model.into();

    active.mobile = Set(payload.mobile);
    if let Some(name) = payload.name { active.name = Set(Some(name)); }
    if let Some(family) = payload.family { active.family = Set(Some(family)); }

    let updated = active.update(&state.db).await.map_err(|err| {
        tracing::error!("Update error: {:?}", err);
        ApiError::internal(None)
    })?;

    Ok(Json(updated.into()))
}

/// بروزرسانی پروفایل کاربر (کاربر لاگین شده)
pub async fn update_profile(
    State(state): State<AppState>,
    Extension(user_id): Extension<i32>,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    payload.validate().map_err(|_| ApiError::unprocessable())?;

    let model = user::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
        .map_err(|err| {
            tracing::error!("Database error: {:?}", err);
            ApiError::internal(None)
        })?
        .ok_or_else(ApiError::not_found)?;

    let mut active: user::ActiveModel = model.into();
    if let Some(name) = payload.name { active.name = Set(Some(name)); }
    if let Some(family) = payload.family { active.family = Set(Some(family)); }

    let updated = active.update(&state.db).await.map_err(|err| {
        tracing::error!("Update error: {:?}", err);
        ApiError::internal(None)
    })?;

    Ok(Json(updated.into()))
}

/// حذف کاربر
pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<UserResponse>, ApiError> {
    let id: i32 = id.parse().map_err(|_| ApiError::unprocessable())?;

    let model = user::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|err| {
            tracing::error!("Database error: {:?}", err);
            ApiError::internal(None)
        })?
        .ok_or_else(ApiError::not_found)?;

    let active: user::ActiveModel = model.clone().into();
    active.delete(&state.db).await.map_err(|err| {
        tracing::error!("Delete error: {:?}", err);
        ApiError::internal(None)
    })?;

    Ok(Json(model.into()))
}
