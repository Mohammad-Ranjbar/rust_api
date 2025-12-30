use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use sea_orm::{ActiveModelTrait, Set,EntityTrait,QueryOrder};
use validator::Validate;
use crate::db::Db;
use crate::entity::user;
use crate::http::requests::user_request::CreateUserRequest;
use crate::http::responses::user_response::UserResponse;

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
Ok(model) => {
        let response: UserResponse = model.into();
        (StatusCode::CREATED, Json(response)).into_response()
                    },
        Err(err) => {
            tracing::error!("db error: {:?}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}


pub async fn index(
    State(db): State<Db>,
) -> impl IntoResponse {
    match user::Entity::find()
        .order_by_desc(user::Column::CreatedAt)
        .all(&db)
        .await
    {
        Ok(models) => {
            // تبدیل Model ها به Resource ها
            let data: Vec<UserResponse> =
                models.into_iter().map(Into::into).collect();

            (StatusCode::OK, Json(data)).into_response()
        }
        Err(err) => {
            tracing::error!("db error: {:?}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
