use serde::Serialize;
use crate::http::responses::user_response::UserResponse;

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserResponse,
}
