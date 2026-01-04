use crate::db::Db;
use crate::http::controllers::auth_controller;

use axum::{
    Router,
    routing::post,
};

pub fn routes() -> Router<Db> {
    Router::new()
    .route("/auth/register", post(auth_controller::register))
    .route("/auth/login", post(auth_controller::login))
}
