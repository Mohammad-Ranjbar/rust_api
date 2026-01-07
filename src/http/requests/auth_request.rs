use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 10, max = 15))]
    pub mobile: String,

    #[validate(length(min = 6))]
    pub password: String,
}
