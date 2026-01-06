use axum::{
    extract::{State, Json, Request},
    response::{IntoResponse, Response},
    http::{StatusCode, HeaderMap},
};
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait,Set,ActiveModelTrait};
use validator::Validate;
use crate::AppState;
use crate::{
    entity::user,
    http::{
        errors::api_error::ApiError,
        requests::auth_request::{RegisterRequest, LoginRequest, RefreshTokenRequest, LogoutRequest, ChangePasswordRequest},
        responses::auth_response::{AuthResponse, TokenValidationResponse, SessionResponse},
        services::auth_service::{AuthService, DeviceInfo},
    },
};

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
    req: Request,
) -> Result<Json<AuthResponse>, ApiError> {
    payload.validate()?;

    let db = &state.db;
    let auth_service = &state.auth_service;

    let existing_user = user::Entity::find()
        .filter(user::Column::Mobile.eq(&payload.mobile))
        .one(db)
        .await?;

    if existing_user.is_some() {
        return Err(ApiError::user_exists());
    }

    let password_hash = AuthService::hash_password(&payload.password)?;

    let user = user::ActiveModel {
        mobile: Set(payload.mobile.clone()),
        name: Set(Some(payload.name)),
        family: Set(Some(payload.family)),
        password_hash: Set(password_hash),
        ..Default::default()
    };

    let user = user.insert(db).await?;

    let device_info = extract_device_info(&req, None);

    let (access_token, refresh_token) = auth_service
        .generate_token_pair(db, user.id, device_info)
        .await?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".into(),
        expires_in: auth_service.jwt_expiry_minutes * 60,
        user_id: user.id,
        mobile: user.mobile,
    }))
}


pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
    req: Request,
) -> Result<Json<AuthResponse>, ApiError> {
    payload.validate()?;

    let db = &state.db;
    let auth_service = &state.auth_service;

    let user = user::Entity::find()
        .filter(user::Column::Mobile.eq(&payload.mobile))
        .one(db)
        .await?
        .ok_or_else(ApiError::invalid_credentials)?;

    if !AuthService::verify_password(&payload.password, &user.password_hash)? {
        return Err(ApiError::invalid_credentials());
    }

    let device_info = extract_device_info(&req, payload.device_id);

    let (access_token, refresh_token) = auth_service
        .generate_token_pair(db, user.id, device_info)
        .await?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".into(),
        expires_in: auth_service.jwt_expiry_minutes * 60,
        user_id: user.id,
        mobile: user.mobile,
    }))
}


pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
    req: Request,
) -> Result<Json<AuthResponse>, ApiError> {
    payload.validate()?;

    let db = &state.db;
    let auth_service = &state.auth_service;

    let refresh = auth_service
        .verify_refresh_token(db, &payload.refresh_token, payload.device_id.clone())
        .await?;

    let user = user::Entity::find_by_id(refresh.user_id)
        .one(db)
        .await?
        .ok_or_else(|| ApiError::unauthorized("User not found".into()))?;

    let device_info = extract_device_info(&req, payload.device_id);

    let access_token = auth_service.create_token(user.id)?;
    let refresh_token = auth_service
        .create_refresh_token(db, user.id, device_info)
        .await?;

    let _ = auth_service
        .revoke_refresh_token(db, &payload.refresh_token)
        .await;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".into(),
        expires_in: auth_service.jwt_expiry_minutes * 60,
        user_id: user.id,
        mobile: user.mobile,
    }))
}



pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Response, ApiError> {
    let db = &state.db;
    let auth_service = &state.auth_service;

    auth_service.revoke_refresh_token(db, &payload.refresh_token).await?;
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}


pub async fn logout_all(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let db = &state.db;
    let auth_service = &state.auth_service;

    let token = extract_token_from_headers(&headers)?;
    let claims = auth_service.verify_token(&token)?;
    let user_id = claims.sub.parse::<i32>()?;

    auth_service.revoke_all_user_refresh_tokens(db, user_id).await?;
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}


pub async fn validate_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TokenValidationResponse>, ApiError> {
    let auth_service = &state.auth_service;

    let token = extract_token_from_headers(&headers)?;
    let claims = auth_service.verify_token(&token)?;
    let user_id = claims.sub.parse::<i32>()?;

    Ok(Json(TokenValidationResponse {
        valid: true,
        user_id,
        expires_at: claims.exp,
        issued_at: claims.iat,
    }))
}


pub async fn get_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let db = &state.db;
    let auth_service = &state.auth_service;

    let token = extract_token_from_headers(&headers)?;
    let claims = auth_service.verify_token(&token)?;
    let user_id = claims.sub.parse::<i32>()?;

    let refresh_tokens = auth_service
        .get_user_refresh_tokens(db, user_id, false)
        .await?;

    let now = chrono::Utc::now();
    let sessions: Vec<SessionResponse> = refresh_tokens
        .into_iter()
        .map(|t| SessionResponse {
            id: t.id,
            device_id: t.device_id,
            ip_address: t.ip_address,
            user_agent: t.user_agent,
            created_at: t.created_at,
            expires_at: t.expires_at,
            is_active: !t.revoked && t.expires_at > now,
        })
        .collect();

    Ok(Json(sessions))
}


pub async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Response, ApiError> {
    payload.validate()?;

    let db = &state.db;
    let auth_service = &state.auth_service;

    let token = extract_token_from_headers(&headers)?;
    let claims = auth_service.verify_token(&token)?;
    let user_id = claims.sub.parse::<i32>()?;

    let user = user::Entity::find_by_id(user_id)
        .one(db)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found".into()))?;

    if !AuthService::verify_password(&payload.current_password, &user.password_hash)? {
        return Err(ApiError::unauthorized("Current password is incorrect".into()));
    }

    let new_password_hash = AuthService::hash_password(&payload.new_password)?;

    let mut user_active: user::ActiveModel = user.into();
    user_active.password_hash = Set(new_password_hash);
    user_active.update(db).await?;

    let _ = auth_service.revoke_all_user_refresh_tokens(db, user_id).await;

    Ok((StatusCode::NO_CONTENT, ()).into_response())
}


// Helper functions
fn extract_device_info(req: &Request, device_id: Option<String>) -> Option<DeviceInfo> {
    let headers = req.headers();
    
    let ip_address = req
        .headers()
        .get("x-forwarded-for")
        .or_else(|| req.headers().get("x-real-ip"))
        .or_else(|| req.headers().get("x-forwarded"))
        .and_then(|value| value.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    let user_agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string());

    if device_id.is_some() || ip_address.is_some() || user_agent.is_some() {
        Some(DeviceInfo {
            device_id,
            ip_address,
            user_agent,
        })
    } else {
        None
    }
}

fn extract_token_from_headers(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| {
            if header.starts_with("Bearer ") {
                Some(header[7..].to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| ApiError::missing_auth_header())
}