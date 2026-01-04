use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .if_not_exists()
                    .col(pk_auto(User::Id))
                    .col(string(User::Mobile).not_null().unique_key())
                    .col(string_null(User::Name))
                    .col(string_null(User::Family))
                    .col(string(User::PasswordHash).not_null())
                    .col(ColumnDef::new(User::CreatedAt)
                        .timestamp()
                        .default(Expr::current_timestamp())
                    )
                    .col(ColumnDef::new(User::UpdatedAt)
                        .timestamp()
                        .default(Expr::current_timestamp())
                        .extra("ON UPDATE CURRENT_TIMESTAMP"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum User {
    #[sea_orm(iden = "users")]
    Table,
    Id,
    Mobile,
    Name,
    Family,
    PasswordHash,
    CreatedAt,
    UpdatedAt,
}

