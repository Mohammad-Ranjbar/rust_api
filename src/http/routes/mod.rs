use axum::Router;
use crate::AppState;

pub mod user_routes;
pub mod auth_routes;

pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(user_routes::routes())
}
