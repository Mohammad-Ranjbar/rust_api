use crate::http::errors::api_error::ApiError;
use crate::entity::user;
use sea_orm::{ EntityTrait, ColumnTrait, QueryFilter};


pub async fn check_unique_mobile(
    db: &sea_orm::DatabaseConnection,
    mobile: &str,
    exclude_id: Option<i32>, // None for create, Some(id) for update
) -> Result<(), ApiError> {
    let mut query = user::Entity::find()
        .filter(user::Column::Mobile.eq(mobile.to_string()));

    if let Some(id) = exclude_id {
        query = query.filter(user::Column::Id.ne(id));
    }

    let exists = query
        .one(db)
        .await
        .map_err(|err| {
            tracing::error!("DB error: {:?}", err);
            ApiError::internal(None)
        })?;

    if exists.is_some() {
        Err(ApiError::UnprocessableEntity(Some(
            "Mobile number already exists".into(),
        )))
    } else {
        Ok(())
    }
}
