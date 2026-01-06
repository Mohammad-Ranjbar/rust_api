use sea_orm::DatabaseConnection;
use crate::services::auth_service::AuthService;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub auth_service: AuthService,
}
