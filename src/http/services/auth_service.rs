use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{ encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use chrono::{Duration, Utc};


const JWT_SECRET: &str = "your_super_secret_key_please_change"; 

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String, // User ID
    exp: usize,  // Expiration time
}

pub struct AuthService;

impl AuthService {
    pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
        hash(password, DEFAULT_COST)
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
        verify(password, hash)
    }

    pub fn create_token(user_id: i32) -> Result<String, jsonwebtoken::errors::Error> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(24))
            .expect("valid timestamp")
            .timestamp();

        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET.as_ref()),
        )
    }

}