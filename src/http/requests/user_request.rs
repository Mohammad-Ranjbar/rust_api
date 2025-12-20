use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 3))]
    pub title: String,

    #[validate(length(max = 500))]
    pub text: Option<String>,
}
