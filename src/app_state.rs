use sea_orm::DatabaseConnection;
use crate::http::services::auth_service::AuthService;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub auth_service: AuthService,
}

impl AppState {
    pub fn new(db: DatabaseConnection, jwt_secret: String) -> Self {
        Self {
            auth_service: AuthService::new(jwt_secret),
            db,
        }
    }
}
