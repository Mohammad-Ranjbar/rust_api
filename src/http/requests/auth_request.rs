use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {

    #[validate(length(min = 11, message = "Title must be at least 11 chars"))]
    pub mobile: String,
    
    pub name:Option<String>,
    
    pub family:Option<String>,

    #[validate(length(min = 6, message = "Password must be at least 6 chars"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    pub mobile: String,
    pub password: String,
}