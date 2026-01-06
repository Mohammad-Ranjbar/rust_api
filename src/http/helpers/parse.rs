use crate::http::errors::api_error::ApiError;

pub fn parse_id(id: &str) -> Result<i32, ApiError> {
    id.parse::<i32>()
        .map_err(|_| ApiError::unprocessable_msg("ID must be a valid integer"))
}
