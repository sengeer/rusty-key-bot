// Импорт из внешнего крейта rand
use rand::{Rng, distributions:: Alphanumeric, rngs::OsRng};

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

// Функция генерации паролей
pub fn generate_password(length: usize, with_special: bool) -> Result<String, AppError> {
    if !(8..=128).contains(&length) {
        return Err(AppError::InvalidArgument(
            "length must be in range 8..=128".to_string(),
        ));
    }

    let mut base = OsRng
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect::<String>();

    if with_special {
        let special = b"!@#$%^&*()-_=+[]{};:,.?";
        let mut bytes = base.into_bytes();
        if !bytes.is_empty() {
            let idx = OsRng.gen_range(0..bytes.len());
            let sp = special[OsRng.gen_range(0..special.len())];
            bytes[idx] = sp;
        }
        base = String::from_utf8(bytes)
            .map_err(|_| AppError::InvalidArgument("invalid UTF-8 generated".to_string()))?;
    }

    Ok(base)
}

// Атрибут теста
#[cfg(test)]
// Тесты
mod tests {
    use super::*;

    #[test]
    fn password_generator_respects_length() {
        let p = generate_password(24, false).expect("must generate");
        assert_eq!(p.len(), 24);
    }

    #[test]
    fn password_generator_validates_length() {
        let err = generate_password(4, false).expect_err("must fail");
        assert!(matches!(err, AppError::InvalidArgument(_)));
    }
}