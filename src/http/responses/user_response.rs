use serde::Serialize;
use chrono_tz::Asia::Tehran;

use crate::entity::user;

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i32,
    pub title: String,
    pub text: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<user::Model> for UserResponse {
    fn from(model: user::Model) -> Self {
        Self {
            id: model.id,
            title: model.title,
            text: model.text,
            created_at: model
                .created_at
                .with_timezone(&Tehran)
                .to_rfc3339(),
            updated_at: model
                .updated_at
                .with_timezone(&Tehran)
                .to_rfc3339(),
        }
    }
}
