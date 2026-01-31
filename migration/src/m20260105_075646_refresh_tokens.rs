use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RefreshTokens::Table)
                    .if_not_exists()
                    .col(pk_auto(RefreshTokens::Id))
                    .col(string(RefreshTokens::TokenHash).unique_key().not_null())
                    .col(integer(RefreshTokens::UserId).not_null())
                    .col(string(RefreshTokens::DeviceId).null())
                    .col(string(RefreshTokens::IpAddress).null())
                    .col(string(RefreshTokens::UserAgent).null())
                    .col(timestamp(RefreshTokens::ExpiresAt).not_null())
                    .col(boolean(RefreshTokens::Revoked).default(false))
                    .col(timestamp(RefreshTokens::CreatedAt).default(Expr::current_timestamp()))
                    .col(timestamp(RefreshTokens::UpdatedAt).default(Expr::current_timestamp()))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_refresh_tokens_user_id")
                            .from(RefreshTokens::Table, RefreshTokens::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RefreshTokens::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum RefreshTokens {
    Table,
    Id,
    TokenHash,
    UserId,
    DeviceId,
    IpAddress,
    UserAgent,
    ExpiresAt,
    Revoked,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}