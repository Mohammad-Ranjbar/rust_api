use axum::{Router, routing::post};
use crate::db::Db;
use crate::http::controllers::user_controller;

pub fn routes() -> Router<Db> {
    Router::new()
        .route("/users", post(user_controller::store))
}
