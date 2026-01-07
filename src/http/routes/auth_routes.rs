use axum::Router;
use axum::routing::{get, post};
use crate::http::controllers::auth_controller;
use crate::http::middleware::auth_middleware::auth_middleware;
use axum::middleware::from_fn;
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(auth_controller::login))

        .nest(
            "/user",
            Router::new()
                .route("/profile", get(auth_controller::profile))
                .layer(from_fn(auth_middleware))
        )
}
