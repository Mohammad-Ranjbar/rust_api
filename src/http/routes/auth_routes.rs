use axum::{
    Router,
    routing::{post, get},
    middleware,
};
use crate::{
    AppState,
    http::{
        controllers::auth_controller,
        middleware::auth_middleware::auth_middleware,
    },
};

pub fn routes() -> Router<AppState> {
    let public_routes = Router::new()
        .route("/register", post(auth_controller::register))
        .route("/login", post(auth_controller::login))
        .route("/refresh", post(auth_controller::refresh_token));

    let protected_routes = Router::new()
        .route("/logout", post(auth_controller::logout))
        .route("/logout-all", post(auth_controller::logout_all))
        .route("/validate", get(auth_controller::validate_token))
        .route("/sessions", get(auth_controller::get_sessions))
        .route("/change-password", post(auth_controller::change_password))
        .layer(middleware::from_fn(auth_middleware));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
}
