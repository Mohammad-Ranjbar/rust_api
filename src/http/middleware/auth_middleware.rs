use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait};

use crate::{
    http::{
        errors::api_error::ApiError,
        services::auth_service::AuthService,
    },
    db::Db,
    entity::user,
};

/// Authentication middleware
pub async fn auth_middleware(
    State(db): State<Db>,
    State(auth_service): State<AuthService>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Extract token
    let token = req.headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| {
            if header.starts_with("Bearer ") {
                Some(header[7..].to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| ApiError::Unauthorized("Missing authorization header".to_string()))?;

    // Verify token
    let claims = auth_service.verify_token(&token)?;
    
    let user_id = claims.sub.parse::<i32>()
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    // Verify user exists - use the fully qualified path
    let user_exists = user::Entity::find()
        .filter(user::Column::Id.eq(user_id))
        .one(&db)
        .await
        .map_err(|err| {
            tracing::error!("Database error checking user: {:?}", err);
            ApiError::internal(None)
        })?
        .is_some();

    if !user_exists {
        return Err(ApiError::Unauthorized("User not found".to_string()));
    }

    // Insert user_id into request extensions for handlers to use
    req.extensions_mut().insert(user_id);

    Ok(next.run(req).await)
}