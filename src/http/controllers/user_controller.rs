use axum::{
    extract::State,
    extract::Path,
    Json,
};

use sea_orm::{ActiveModelTrait, Set,EntityTrait,QueryOrder};
use validator::Validate;
use crate::db::Db;
use crate::entity::user;
use crate::http::requests::user_request::{CreateUserRequest,UpdateUserRequest};
use crate::http::responses::user_response::UserResponse;
use crate::http::errors::api_error::ApiError;
use crate::http::helpers::parse::parse_id;

pub async fn store(
    State(db): State<Db>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    payload
        .validate()
        .map_err(|_| ApiError::UnprocessableEntity(
            "Invalid input data".to_string(),
        ))?;

    let user = user::ActiveModel {
        mobile: Set(payload.mobile),
        name: Set(payload.name),
        family: Set(payload.family),
        ..Default::default()
    };

    let model = user.insert(&db).await.map_err(|err| {
        tracing::error!("db error: {:?}", err);
        ApiError::internal(None)
    })?;

    Ok(Json(model.into()))
}

pub async fn update(
    State(db): State<Db>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {

    payload
        .validate()
        .map_err(|_| ApiError::UnprocessableEntity("Invalid data".to_string()))?;

    let id = parse_id(&id)?;

    let model = user::Entity::find_by_id(id)
        .one(&db)
        .await
        .map_err(|_| ApiError::internal(None))?
        .ok_or_else(|| ApiError::NotFound("User not available".to_string()))?;

    let mut active: user::ActiveModel = model.into();

    active.mobile = Set(payload.mobile);

    if let Some(name) = payload.name {
        active.name = Set(Some(name));
    }

        if let Some(family) = payload.family {
        active.family = Set(Some(family));
    }

    // save
    let updated = active
        .update(&db)
        .await
        .map_err(|_| ApiError::internal(None))?;

    Ok(Json(updated.into()))
}

pub async fn index(
    State(db): State<Db>,
) -> Result<Json<Vec<UserResponse>>, ApiError> {
    let models = user::Entity::find()
        .order_by_desc(user::Column::CreatedAt)
        .all(&db)
        .await
        .map_err(|err| {
            tracing::error!("db error: {:?}", err);
            ApiError::internal(None)
        })?;

    let data = models.into_iter().map(Into::into).collect();

    Ok(Json(data))
}

pub async fn show(
    State(db): State<Db>,
    Path(id): Path<String>,
) -> Result<Json<UserResponse>, ApiError> {
    let id = parse_id(&id)?;

    let model = user::Entity::find_by_id(id)
        .one(&db)
        .await
        .map_err(|_| ApiError::internal(None))?;

    let model = model.ok_or_else(|| ApiError::NotFound("User not available".to_string()))?;

    Ok(Json(model.into()))
}

pub async fn delete(
    State(db): State<Db>,
    Path(id): Path<String>,
) -> Result<Json<UserResponse>, ApiError> {
    let id = parse_id(&id)?;

    let model = user::Entity::find_by_id(id)
        .one(&db)
        .await
        .map_err(|_| ApiError::internal(None))?;

    let model = model.ok_or_else(|| ApiError::NotFound("User not available".to_string()))?;
    
    let active:user::ActiveModel = model.clone().into();
    
    active.delete(&db).await.map_err(|_| ApiError::internal(None))?;
    
    Ok(Json(model.into()))
}