use axum::http::HeaderMap;
use chrono::Utc;
use rand_core::{OsRng, RngCore};
use sha2::{Sha256, Digest};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use crate::http::types::session::{SessionInfo, IssuedTokens};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};

#[derive(Clone, Debug)]
pub struct AuthService {
    pub jwt_secret: String, // اضافه شد
}

impl AuthService {
    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret }
    }

    /// هش سریع SHA256 برای پسورد یا توکن
    pub fn hash_password(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        STANDARD.encode(hasher.finalize())
    }

    /// بررسی پسورد با هش SHA256
    pub fn verify_password(&self, password: &str, hash: &str) -> bool {
        Self::hash_password(password) == hash
    }

    /// تولید توکن JWT
    pub fn create_token(&self, user_id: i32) -> Result<String, jsonwebtoken::errors::Error> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Claims {
            sub: i32,
            exp: usize,
        }

        let claims = Claims {
            sub: user_id,
            exp: (Utc::now().timestamp() + 3600) as usize, // 1 ساعت اعتبار
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )
    }

    /// رمزگشایی JWT
    pub fn decode_token(&self, token: &str) -> Result<i32, jsonwebtoken::errors::Error> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Claims {
            sub: i32,
            exp: usize,
        }

        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &Validation::default(),
        )?;
        Ok(data.claims.sub)
    }

    /// تولید توکن رفرش تصادفی
    pub fn generate_refresh_token(&self) -> String {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        STANDARD.encode(bytes)
    }

    /// هش توکن رفرش
    pub fn hash_refresh_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        STANDARD.encode(hasher.finalize())
    }

    /// استخراج اطلاعات جلسه
    pub fn extract_session_info(
        &self,
        headers: &HeaderMap,
        addr: &std::net::SocketAddr,
    ) -> SessionInfo {
        let device_id = headers
            .get("x-device-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let user_agent = headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let ip_address = Some(addr.ip().to_string());

        SessionInfo {
            device_id,
            ip_address,
            user_agent,
        }
    }

    /// صدور توکن دسترسی و رفرش
    pub fn issue_tokens(
        &self,
        user_id: i32,
        headers: &HeaderMap,
        addr: &std::net::SocketAddr,
    ) -> Result<IssuedTokens, jsonwebtoken::errors::Error> {
        let access_token = self.create_token(user_id)?;
        let refresh_token = self.generate_refresh_token();
        let session = self.extract_session_info(headers, addr);

        Ok(IssuedTokens {
            access_token,
            refresh_token,
            session,
        })
    }
}
