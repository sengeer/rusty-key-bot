// Импорт из внешнего крейта
use async_trait::async_trait;

// Групповой импорт модулей
use crate::{
    domain::{EncryptedEntry, EncryptedField, MasterRecord, PlainEntryInput, PlainEntryView},
    errors::AppError,
};

#[async_trait]
// Трейт VaultRepository
pub trait VaultRepository: Send + Sync {
    async fn upsert_master(&self, user_id: i64, record: MasterRecord) -> Result<(), AppError>;
    async fn get_master(&self, user_id: i64) -> Result<Option<MasterRecord>, AppError>;
    async fn upsert_entry(&self, user_id: i64, entry: EncryptedEntry) -> Result<(), AppError>;
    async fn get_entry(
        &self,
        user_id: i64,
        service: &str,
    ) -> Result<Option<EncryptedEntry>, AppError>;
    async fn list_services(&self, user_id: i64) -> Result<Vec<String>, AppError>;
    async fn delete_entry(&self, user_id: i64, service: &str) -> Result<bool, AppError>;
}