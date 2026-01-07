use axum::Router;
use axum::routing::{get, post};
use crate::http::controllers::auth_controller;
use crate::http::middleware::auth_middleware::auth_middleware;
use axum::middleware::from_fn_with_state;
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        // این روت بدون middleware است
        .route("/login", post(auth_controller::login))

        // روت‌های محافظت شده
        .nest(
            "/user",
            Router::new()
                .route("/profile", get(auth_controller::profile))
                .layer(from_fn_with_state(state.clone(), auth_middleware))
        )
}
