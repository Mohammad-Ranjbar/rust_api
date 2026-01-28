#[derive(Deserialize, Validate)]
pub struct RefreshTokenRequest {
    #[validate(length(min = 10))]
    pub refresh_token: String,
}
