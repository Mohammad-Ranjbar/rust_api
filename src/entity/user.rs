use sea_orm::entity::prelude::*;
use serde::Serialize;
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]

#[sea_orm(table_name = "users")]

pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,

    pub title: String,
    pub text: Option<String>,

    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {}
impl sea_orm::RelationTrait for Relation {
    fn def(&self) -> sea_orm::RelationDef {
        panic!("No relations defined")
    }
}

impl ActiveModelBehavior for ActiveModel {}
