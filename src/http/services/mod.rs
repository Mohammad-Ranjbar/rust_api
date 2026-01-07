pub mod auth_service;

use std::sync::OnceLock;
use auth_service::AuthService;

static AUTH_SERVICE: OnceLock<AuthService> = OnceLock::new();

pub fn init_auth_service(jwt_secret: String) {
    AUTH_SERVICE
        .set(AuthService::new(jwt_secret))
        .expect("AuthService already initialized");
}

pub fn auth_service() -> &'static AuthService {
    AUTH_SERVICE
        .get()
        .expect("AuthService not initialized")
}
