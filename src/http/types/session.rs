#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub device_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}


pub struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub session: SessionInfo,
}