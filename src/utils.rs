// Импорт из внешнего крейта rand
use rand::{Rng, distributions:: Alphanumeric, rngs::OsRng};

// Импорт из модуля errors
use crate::errors::AppError;

// Фунция генерации паролей
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

// Атрибуция теста
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