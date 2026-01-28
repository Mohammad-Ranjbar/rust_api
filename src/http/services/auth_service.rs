use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use chrono::Utc;
use crate::http::types::claims::Claims;
use rand_core::{OsRng, RngCore};

#[derive(Clone, Debug)]
pub struct AuthService {
    jwt_secret: String,
}

impl AuthService {

    pub fn generate_refresh_token(&self) -> String {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        base64::encode(bytes)
    }

    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret }
    }

    pub fn create_token(&self, user_id: i32) -> Result<String, jsonwebtoken::errors::Error> {
        let claims = Claims {
            sub: user_id,
            exp: (Utc::now().timestamp() + 3600) as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )
    }

    pub fn decode_token(&self, token: &str) -> Result<i32, jsonwebtoken::errors::Error> {
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &Validation::default(),
        )?;
        Ok(data.claims.sub)
    }

    pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
        Ok(hash)
    }

    pub fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool, argon2::password_hash::Error> {
        let parsed = PasswordHash::new(password_hash)?;
        Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
    }
}
