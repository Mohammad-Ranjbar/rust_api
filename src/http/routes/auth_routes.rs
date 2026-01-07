use axum::{Router, routing::post};
use crate::{AppState, http::controllers::auth_controller};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(auth_controller::login))
}
