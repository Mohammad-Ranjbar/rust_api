use validator::Validate;
use serde::Deserialize;

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateProfileRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,

     #[validate(length(min = 1, max = 255))]
    pub family: Option<String>,
}
