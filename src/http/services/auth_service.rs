use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use rand_core::OsRng;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Serialize, Deserialize};

#[derive(Clone)]
pub struct AuthService {
    jwt_secret: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i32,
    exp: usize,
}
impl AuthService {
    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret }
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
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string();
        Ok(password_hash)
    }

    pub fn verify_password(
        &self,
        password: &str,
        password_hash: &str,
    ) -> Result<bool, argon2::password_hash::Error> {
        let parsed_hash = PasswordHash::new(password_hash)?;
        Ok(
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
        )
    }

    pub fn create_token(&self, user_id: i32) -> Result<String, jsonwebtoken::errors::Error> {

        let claims = Claims {
            sub: user_id,
            exp: (chrono::Utc::now().timestamp() + 3600) as usize,
        };

        Ok(jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )?)
    }
}