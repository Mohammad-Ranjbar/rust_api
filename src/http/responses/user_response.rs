use serde::Serialize;
use chrono_tz::Asia::Tehran;

use crate::entity::user;

#[derive(Debug,Serialize)]
pub struct UserResponse {
    pub id: i32,

    pub mobile: String,

    pub name: Option<String>,

    pub family: Option<String>,

    pub created_at: String,

    pub updated_at: String,
}

impl From<user::Model> for UserResponse {
    fn from(model: user::Model) -> Self {
        Self {
            id: model.id,
            mobile: model.mobile,
            name: model.name,
            family: model.family,
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
