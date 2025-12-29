use serde::Serialize;

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i32,
    pub title: String,
    pub text: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
