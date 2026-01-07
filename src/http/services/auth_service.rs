use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use rand_core::OsRng;

#[derive(Clone)]
pub struct AuthService {
    jwt_secret: String,
}

impl AuthService {
    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret }
    }

    pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default(); // Argon2id, safe defaults
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
        #[derive(serde::Serialize)]
        struct Claims {
            sub: i32,
            exp: usize,
        }

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