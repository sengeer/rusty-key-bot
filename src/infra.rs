// Импорт трейта
use std::str::FromStr;

// Импорты API из крейтов
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use async_trait::async_trait;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, AeadCore},
};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

// Импорт API из модулей
use crate::{
    app::{CryptoPort, VaultRepository},
    domain::{EncryptedEntry, EncryptedField, MasterRecord},
    errors::AppError,
};

// Создание пула подключений к SQLite
pub async fn create_pool(database_url: &str) -> Result<SqlitePool, AppError> {
    // Настройка SqliteConnectOptions
    let options = SqliteConnectOptions::from_str(database_url)
        .map_err(|e| AppError::Storage(e.to_string()))?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal);

    // Создание пула
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(AppError::from)
}

// Выполнение миграций БД
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), AppError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| AppError::Storage(e.to_string()))
}

// Атрибут derive с Clone
#[derive(Clone)]
// Структура SqliteVaultRepository
pub struct SqliteVaultRepository {
    pool: SqlitePool,
}

// Имплементация SqliteVaultRepository для хранилища под SQLite
impl SqliteVaultRepository {
    // Ассоциированная функция-конструктор
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

// Атрибут async_trait
#[async_trait]
// Имплементация VaultRepository
// Набор методов с SQL-запросами к БД
impl VaultRepository for SqliteVaultRepository {
    // Добавление или обновление мастер-пароля
    async fn upsert_master(&self, user_id: i64, record: MasterRecord) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO users (telegram_id, master_hash, master_salt, key_salt)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(telegram_id) DO UPDATE SET
              master_hash = excluded.master_hash,
              master_salt = excluded.master_salt,
              key_salt = excluded.key_salt
            "#,
        )
        .bind(user_id)
        .bind(record.hash)
        .bind(record.master_salt)
        .bind(record.key_salt)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Получение мастер-пароля
    async fn get_master(&self, user_id: i64) -> Result<Option<MasterRecord>, AppError> {
        let row = sqlx::query(
            "SELECT master_hash, master_salt, key_salt FROM users WHERE telegram_id = ?1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| MasterRecord {
            hash: r.get("master_hash"),
            master_salt: r.get("master_salt"),
            key_salt: r.get("key_salt"),
        }))
    }

    // Добавление или обновление записи
    async fn upsert_entry(&self, user_id: i64, entry: EncryptedEntry) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO entries (
              user_id, service,
              login_nonce, login_cipher,
              password_nonce, password_cipher,
              note_nonce, note_cipher
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(user_id, service) DO UPDATE SET
              login_nonce = excluded.login_nonce,
              login_cipher = excluded.login_cipher,
              password_nonce = excluded.password_nonce,
              password_cipher = excluded.password_cipher,
              note_nonce = excluded.note_nonce,
              note_cipher = excluded.note_cipher
            "#,
        )
        .bind(user_id)
        .bind(entry.service)
        .bind(entry.login.nonce)
        .bind(entry.login.cipher)
        .bind(entry.password.nonce)
        .bind(entry.password.cipher)
        .bind(entry.note.as_ref().map(|n| n.nonce.clone()))
        .bind(entry.note.as_ref().map(|n| n.cipher.clone()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Получение записи
    async fn get_entry(
        &self,
        user_id: i64,
        service: &str,
    ) -> Result<Option<EncryptedEntry>, AppError> {
        let row = sqlx::query(
            r#"
            SELECT service, login_nonce, login_cipher, password_nonce, password_cipher, note_nonce, note_cipher
            FROM entries
            WHERE user_id = ?1 AND service = ?2
            "#,
        )
        .bind(user_id)
        .bind(service)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let note_nonce: Option<Vec<u8>> = r.get("note_nonce");
            let note_cipher: Option<Vec<u8>> = r.get("note_cipher");
            EncryptedEntry {
                service: r.get("service"),
                login: EncryptedField {
                    nonce: r.get("login_nonce"),
                    cipher: r.get("login_cipher"),
                },
                password: EncryptedField {
                    nonce: r.get("password_nonce"),
                    cipher: r.get("password_cipher"),
                },
                note: match (note_nonce, note_cipher) {
                    (Some(nonce), Some(cipher)) => Some(EncryptedField { nonce, cipher }),
                    _ => None,
                },
            }
        }))
    }

    // Получение списка сервисов
    async fn list_services(&self, user_id: i64) -> Result<Vec<String>, AppError> {
        let rows = sqlx::query("SELECT service FROM entries WHERE user_id = ?1 ORDER BY service")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get("service")).collect())
    }

    // Удаление записи
    async fn delete_entry(&self, user_id: i64, service: &str) -> Result<bool, AppError> {
        let result = sqlx::query("DELETE FROM entries WHERE user_id = ?1 AND service = ?2")
            .bind(user_id)
            .bind(service)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// Атрибут derive с Clone и Default
#[derive(Clone, Default)]
// Пустая структура CryptoManager
pub struct CryptoManager;

// Имплементация CryptoManager
impl CryptoManager {
    // Генерация соли
    fn random_salt() -> Vec<u8> {
        let salt = SaltString::generate(&mut OsRng);
        salt.as_str().as_bytes().to_vec()
    }
}

// Имплементация CryptoPort
impl CryptoPort for CryptoManager {
    // Создание записи мастер-пароля
    fn create_master_record(&self, master_password: &str) -> Result<MasterRecord, AppError> {
        if master_password.is_empty() {
            return Err(AppError::EmptyMasterPassword);
        }

        let master_salt = Self::random_salt();
        let key_salt = Self::random_salt();
        let master_salt_str = std::str::from_utf8(&master_salt)
            .map_err(|_| AppError::Crypto)?
            .to_string();
        let salt = SaltString::from_b64(&master_salt_str).map_err(|_| AppError::Crypto)?;

        let hash = Argon2::default()
            .hash_password(master_password.as_bytes(), &salt)
            .map_err(|_| AppError::Crypto)?
            .to_string();

        Ok(MasterRecord {
            hash,
            master_salt,
            key_salt,
        })
    }

    // Проверка мастер-пароля
    fn verify_master_password(
        &self,
        master_password: &str,
        record: &MasterRecord,
    ) -> Result<bool, AppError> {
        let parsed = PasswordHash::new(&record.hash).map_err(|_| AppError::Crypto)?;
        Ok(Argon2::default()
            .verify_password(master_password.as_bytes(), &parsed)
            .is_ok())
    }

    // Получение симметричного ключа для записей
    fn derive_entry_key(
        &self,
        master_password: &str,
        key_salt: &[u8],
    ) -> Result<[u8; 32], AppError> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(master_password.as_bytes(), key_salt, &mut key)
            .map_err(|_| AppError::Crypto)?;
        Ok(key)
    }

    // Зашифровка
    fn encrypt(
        &self,
        key: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedField, AppError> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        };
        let encrypted = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| AppError::Crypto)?;
        Ok(EncryptedField {
            nonce: nonce.to_vec(),
            cipher: encrypted,
        })
    }

    // Расшифровка
    fn decrypt(
        &self,
        key: &[u8; 32],
        field: &EncryptedField,
        aad: &[u8],
    ) -> Result<Vec<u8>, AppError> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = chacha20poly1305::Nonce::from_slice(&field.nonce);
        let payload = chacha20poly1305::aead::Payload {
            msg: &field.cipher,
            aad,
        };
        cipher.decrypt(nonce, payload).map_err(|_| AppError::Crypto)
    }
}

// Атрибут теста
#[cfg(test)]
// Тесты
mod tests {
    use crate::app::CryptoPort;

    use super::CryptoManager;

    #[test]
    fn crypto_roundtrip_works() {
        let crypto = CryptoManager;
        let key = crypto
            .derive_entry_key("super-master", b"fixed-test-salt")
            .expect("key");
        let aad = b"user:service";
        let field = crypto.encrypt(&key, b"hello", aad).expect("enc");
        let plain = crypto.decrypt(&key, &field, aad).expect("dec");
        assert_eq!(plain, b"hello");
    }
}