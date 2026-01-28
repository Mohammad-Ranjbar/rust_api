use axum::Router;
use axum::routing::{get, post};
use crate::http::controllers::auth_controller;
use crate::http::middleware::auth_middleware::auth_middleware;
use crate::http::controllers::user_controller;
use axum::middleware::from_fn;
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(auth_controller::login))
        .route("/refresh-token", post(auth_controller::refresh_token))
        .nest(
            "/user",
            Router::new()
                .route("/profile", get(auth_controller::profile))
                .route("/update-profile", post(user_controller::update_profile))
                .layer(from_fn(auth_middleware))
        )
}
