use axum::{
    Router,
    routing::get,
};
use crate::{
    AppState,
    http::controllers::user_controller,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/users",
            get(user_controller::index)
                .post(user_controller::store),
        )
        .route(
            "/users/{id}",
            get(user_controller::show)
                .put(user_controller::update)
                .delete(user_controller::delete),
        )
}
