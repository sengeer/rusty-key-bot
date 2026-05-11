// Импорт из внешнего крейта thiserror
use thiserror::Error;

// Aтрибуция встроенных трейтов
#[derive(Debug, Error)]
// Таксономия ошибок
pub enum AppError {
    #[error("пустое название сервиса")]
    EmptyServiceName,
    #[error("пустой логин")]
    EmptyLogin,
    #[error("пустой пароль")]
    EmptyPassword,
    #[error("пустой мастер-пароль")]
    EmptyMasterPassword,
    #[error("мастер-пароль не установлен")]
    MasterPasswordNotSet,
    #[error("неверный мастер-пароль")]
    InvalidMasterPassword,
    #[error("для смены мастер-пароля требуется подтверждение текущего")]
    CurrentMasterPasswordRequired,
    #[error("запись не найдена")]
    EntryNotFound,
    #[error("неверный аргумент: {0}")]
    InvalidArgument(String),
    #[error("ошибка криптографии")]
    Crypto,
    #[error("ошибка хранилища: {0}")]
    Storage(String),
}

// Имплементация конвертации ошибки БД в AppError
// From::from из sqlx::Error делает AppError::Storage("текст ошибки"...)
impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        Self::Storage(value.to_string())
    }
}
