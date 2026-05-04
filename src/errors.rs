// Импорт из внешнего крейта thiserror
use thiserror::Error;

// Aтрибуция встроенных трейтов
#[derive(Debug, Error)]
// Таксономия ошибок
pub enum AppError {
    #[error("service name is empty")]
    EmptyServiceName,
    #[error("login is empty")]
    EmptyLogin,
    #[error("password is empty")]
    EmptyPassword,
    #[error("master password is empty")]
    EmptyMasterPassword,
    #[error("master password is not set")]
    MasterPasswordNotSet,
    #[error("master password is invalid")]
    InvalidMasterPassword,
    #[error("entry not found")]
    EntryNotFound,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("crypto error")]
    Crypto,
    #[error("storage error: {0}")]
    Storage(String),
}

// Имплементация конвертации ошибки БД в AppError
// From::from из sqlx::Error делает AppError::Storage("текст ошибки"...)
impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        Self::Storage(value.to_string())
    }
}
