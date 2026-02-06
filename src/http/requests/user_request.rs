use serde::Deserialize;
use validator::Validate;

    #[derive(Debug, Deserialize, Validate)]
    pub struct CreateUserRequest {
        #[validate(length(min = 11))]
        pub mobile: String,

        #[validate(length(max = 200))]
        pub name: Option<String>,

        #[validate(length(max = 200))]
        pub family: Option<String>,

        #[validate(length(min = 6))]
        pub password:String
    }
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(length(min = 11))]
    pub mobile: String,

    #[validate(length(max = 200))]
    pub name: Option<String>,

    #[validate(length(max = 200))]
    pub family: Option<String>,
}