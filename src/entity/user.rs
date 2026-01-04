use sea_orm::entity::prelude::*;
use serde::Serialize;
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]

#[sea_orm(table_name = "users")]

pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    
    pub name: Option<String>,
    pub family: Option<String>,

    pub mobile: String,
    pub password_hash: String, 

    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {}
impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        panic!("No relations defined")
    }
}

impl ActiveModelBehavior for ActiveModel {}
