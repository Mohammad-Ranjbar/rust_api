use crate::db::Db;
use crate::http::controllers::user_controller;
use axum::{
    Router,
    routing::{get, post},
};

pub fn routes() -> Router<Db> {
    Router::new()
        .route(
            "/users",
            post(user_controller::store).get(user_controller::index),
        )
        .route("/users/{id}", get(user_controller::show))
}
