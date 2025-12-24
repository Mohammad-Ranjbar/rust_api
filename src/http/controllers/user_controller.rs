use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use sea_orm::{ActiveModelTrait, Set};
use validator::Validate;
use crate::db::Db;
use crate::entity::user;
use crate::http::requests::user_request::CreateUserRequest;

pub async fn store(
    State(db): State<Db>,
    Json(payload): Json<CreateUserRequest>,
) -> impl IntoResponse {
    if payload.validate().is_err() {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }

    let user = user::ActiveModel {
        title: Set(payload.title),
        text: Set(payload.text),
        ..Default::default()
    };

    match user.insert(&db).await {
        Ok(model) => (StatusCode::CREATED, Json(model)).into_response(),
        Err(err) => {
            tracing::error!("db error: {:?}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
