use crate::http::routes;
use std::env;
use axum::Router;
use sea_orm::Database;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::db::Db;
use crate::http::services::auth_service::AuthService;

mod db;
mod entity;
mod http;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub auth_service: AuthService,
}

impl AppState {
    pub fn new(db: Db, jwt_secret: String) -> Self {
        Self {
            db,
            auth_service: AuthService::new(jwt_secret, 15, 7),
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let database_url =
        env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let jwt_secret =
        env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let db: Db = Database::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    tracing::info!("Database connected");

    // 👇 این خط کلیدی است
    let state = AppState::new(db, jwt_secret);

    let app: Router = routes::routes()
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind port");

    tracing::info!("Server running on http://0.0.0.0:3000");

    axum::serve(listener, app)
        .await
        .unwrap();
}
