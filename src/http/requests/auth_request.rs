use serde::Deserialize;
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 1, message = "Mobile number is required"))]
    pub mobile: String,
    
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    
    #[validate(length(min = 1, message = "Family is required"))]
    pub family: String,
    
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 1, message = "Mobile number is required"))]
    pub mobile: String,
    
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
    
    pub device_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RefreshTokenRequest {
    #[validate(length(min = 1, message = "Refresh token is required"))]
    pub refresh_token: String,
    
    pub device_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LogoutRequest {
    #[validate(length(min = 1, message = "Refresh token is required"))]
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 6, message = "Current password must be at least 6 characters"))]
    pub current_password: String,
    
    #[validate(length(min = 6, message = "New password must be at least 6 characters"))]
    pub new_password: String,
    
    // We'll check this manually in the controller since validator doesn't support cross-field validation easily
    pub confirm_password: String,
}

// Add this to check password confirmation
impl ChangePasswordRequest {
    pub fn validate_password_match(&self) -> Result<(), ValidationError> {
        if self.new_password != self.confirm_password {
            let mut error = ValidationError::new("passwords_mismatch");
            error.message = Some("Passwords do not match".into());
            return Err(error);
        }
        Ok(())
    }
}