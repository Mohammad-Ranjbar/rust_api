use axum::{
    extract::{State, Path},
    Json,
};
use crate::app_state::AppState;
use sea_orm::{ActiveModelTrait, Set, EntityTrait, QueryOrder};
use validator::Validate;
use crate::entity::user;
use crate::http::requests::user_request::{CreateUserRequest, UpdateUserRequest};
use crate::http::requests::update_profile_request::UpdateProfileRequest;
use crate::http::responses::user_response::UserResponse;
use crate::http::errors::api_error::ApiError;
use crate::http::helpers::parse::parse_id;
use crate::http::services::auth_service::AuthService;
use axum::extract::Extension;

pub async fn update_profile(
    State(state): State<AppState>,
    Extension(user_id): Extension<i32>,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    payload.validate().map_err(|_| ApiError::unprocessable())?;

    let user_model = user::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(ApiError::not_found)?;

    let mut user_active: user::ActiveModel = user_model.into();

    if let Some(name) = payload.name {
        user_active.name = Set(Some(name));
    }

    if let Some(family) = payload.family {
        user_active.family = Set(Some(family));
    }

    let updated_user = user_active
        .update(&state.db)
        .await
        .map_err(|err| {
            tracing::error!("User update error: {:?}", err);
            ApiError::internal(None)
        })?;

    Ok(Json(updated_user.into()))
}

pub async fn store(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    payload
        .validate()
        .map_err(|_| ApiError::unprocessable())?;

    let password_hash = AuthService::hash_password(&payload.password)
        .map_err(|err| {
            tracing::error!("Failed to hash password: {:?}", err);
            ApiError::internal(None)
        })?;
    
    let user = user::ActiveModel {
        mobile: Set(payload.mobile),
        name: Set(payload.name),
        family: Set(payload.family),
        password_hash: Set(password_hash),
        ..Default::default()
    };
    let db = &state.db;
    let model = user.insert(db).await.map_err(|err| {
        tracing::error!("db error: {:?}", err);
        ApiError::internal(None)
    })?;

    Ok(Json(model.into()))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {

    payload
        .validate()
        .map_err(|_| ApiError::unprocessable())?;

    let id: i32 = parse_id(&id)?;
    let db = &state.db;
    let model = user::Entity::find_by_id(id)
        .one(db)
        .await
        .map_err(|err| {
            tracing::error!("Database error: {:?}", err);
            ApiError::internal(None)
        })?
        .ok_or_else(|| ApiError::not_found())?;

    let mut active: user::ActiveModel = model.into();

    active.mobile = Set(payload.mobile);

    if let Some(name) = payload.name {
        active.name = Set(Some(name));
    }

    if let Some(family) = payload.family {
        active.family = Set(Some(family));
    }

    let updated = active
        .update(db)
        .await
        .map_err(|err| {
            tracing::error!("Update error: {:?}", err);
            ApiError::internal(None)
        })?;

    Ok(Json(updated.into()))
}

pub async fn index(
    State(state): State<AppState>,
) -> Result<Json<Vec<UserResponse>>, ApiError> {
    let db = &state.db;
    let models = user::Entity::find()
        .order_by_desc(user::Column::CreatedAt)
        .all(db)
        .await
        .map_err(|err| {
            tracing::error!("db error: {:?}", err);
            ApiError::internal(None)
        })?;

    let data = models.into_iter().map(Into::into).collect();

    Ok(Json(data))
}

pub async fn show(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<UserResponse>, ApiError> {
    let id = parse_id(&id)?;
    let db = &state.db;
    let model = user::Entity::find_by_id(id)
        .one(db)
        .await
        .map_err(|err| {
            tracing::error!("Database error: {:?}", err);
            ApiError::internal(None)
        })?
        .ok_or_else(|| ApiError::not_found())?;

    Ok(Json(model.into()))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<UserResponse>, ApiError> {
    let id = parse_id(&id)?;
    let db = &state.db;
    let model = user::Entity::find_by_id(id)
        .one(db)
        .await
        .map_err(|err| {
            tracing::error!("Database error: {:?}", err);
            ApiError::internal(None)
        })?
        .ok_or_else(|| ApiError::not_found())?;
    
    let active: user::ActiveModel = model.clone().into();
    active.delete(db).await.map_err(|err| {
        tracing::error!("Delete error: {:?}", err);
        ApiError::internal(None)
    })?;
    
    Ok(Json(model.into()))
}
