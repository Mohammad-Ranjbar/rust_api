// src/bin/seed.rs
use sea_orm::{Database, ActiveModelTrait, Set};
use chrono::Utc;
use fake::{Fake, faker::{name::en::{FirstName, LastName}, phone_number::en::PhoneNumber}};
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose, Engine as _};
use std::env;
use dotenv::dotenv;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// mod users {
//     use sea_orm::entity::prelude::*;
//     #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
//     #[sea_orm(table_name = "users")]
//     pub struct Model {
//         #[sea_orm(primary_key)]
//         pub id: i32,
//         pub name: Option<String>,
//         pub family: Option<String>,
//         pub mobile: String,
//         pub password_hash: String,
//         pub created_at: DateTimeUtc,
//         pub updated_at: DateTimeUtc,
//     }
//     #[derive(Copy, Clone, Debug, EnumIter)]
//     pub enum Relation {}
//     impl RelationTrait for Relation { fn def(&self) -> RelationDef { panic!("No relations") } }
//     impl ActiveModelBehavior for ActiveModel {}
// }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let database_url = env::var("DATABASE_URL")?;
    let db = Database::connect(&database_url).await?;

    let count = env::args().nth(1).and_then(|v| v.parse::<usize>().ok()).unwrap_or(50);

    for _ in 0..count {
        let first: String = FirstName().fake();
        let last: String = LastName().fake();
        let mobile_raw: String = PhoneNumber().fake();
        let mobile = mobile_raw.chars().filter(|c| c.is_ascii_digit()).collect::<String>();
        let now = Utc::now();

        let user = users::ActiveModel {
            name: Set(Some(first)),
            family: Set(Some(last)),
            mobile: Set(mobile),
            password_hash: Set(hash_password("password")),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        let _ = user.insert(&db).await;
    }

    Ok(())
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    general_purpose::STANDARD.encode(hasher.finalize())
}
