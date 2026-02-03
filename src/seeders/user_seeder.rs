use sea_orm::{
    ActiveModelTrait,
    Set,
};
use chrono::Utc;
use fake::{
    Fake,
    faker::{
        name::en::{FirstName, LastName},
        phone_number::en::PhoneNumber,
    },
};

use crate::db::Db;
use crate::entity::user;
use crate::http::services::auth_service::AuthService;

pub async fn seed_users(db: &Db, count: usize) -> anyhow::Result<()> {
    tracing::info!("Seeding {} fake users…", count);

    for _ in 0..count {
        let first_name: String = FirstName().fake();
        let last_name: String = LastName().fake();
        let mobile_raw: String = PhoneNumber().fake();

        let mobile = mobile_raw
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>();

        let now = Utc::now();
        let password_hash = AuthService::hash_password("password");
        let user = user::ActiveModel {
            name: Set(Some(first_name)),
            family: Set(Some(last_name)),
            mobile: Set(mobile),
            password_hash: Set(password_hash),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        // Ignore duplicates (mobile should usually be UNIQUE)
        let _ = user.insert(db).await;
    }

    tracing::info!("User seeding completed");
    Ok(())
}
