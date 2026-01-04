use serde::Serialize;

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: i32,
    pub mobile: String
}