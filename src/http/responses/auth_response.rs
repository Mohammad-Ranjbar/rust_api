use serde::Serialize;
use crate::http::responses::user_response::UserResponse;

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserResponse,
}
