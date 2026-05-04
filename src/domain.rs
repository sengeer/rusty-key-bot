// Импорт из модуля errors
use crate::errors::AppError;

// Aтрибуция встроенных трейтов
#[derive(Debug, Clone)]
// Публичная структура PlainEntryInput
pub struct PlainEntryInput {
    pub service: String,
    pub login: String,
    pub password: String,
    pub note: Option<String>,
}

// Имплементация PlainEntryInput
impl PlainEntryInput {
    pub fn validate(self) -> Result<Self, AppError> {
        if self.service.trim().is_empty() {
            return Err(AppError::EmptyServiceName);
        }
        if self.login.trim().is_empty() {
            return Err(AppError::EmptyLogin);
        }
        if self.password.is_empty() {
            return Err(AppError::EmptyPassword);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub struct PlainEntryView {
    pub service: String,
    pub login: String,
    pub password: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MasterRecord {
    pub hash: String,
    pub master_salt: Vec<u8>,
    pub key_salt: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EncryptedField {
    pub nonce: Vec<u8>,
    pub cipher: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EncryptedEntry {
    pub service: String,
    pub login: EncryptedField,
    pub password: EncryptedField,
    pub note: Option<EncryptedField>,
}
