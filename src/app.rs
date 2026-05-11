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

// Трейт крипто-слоя CryptoPort
pub trait CryptoPort: Send + Sync {
    fn create_master_record(&self, master_password: &str) -> Result<MasterRecord, AppError>;
    fn verify_master_password(
        &self,
        master_password: &str,
        record: &MasterRecord,
    ) -> Result<bool, AppError>;
    fn derive_entry_key(
        &self,
        master_password: &str,
        key_salt: &[u8],
    ) -> Result<[u8; 32], AppError>;
    fn encrypt(
        &self,
        key: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedField, AppError>;
    fn decrypt(
        &self,
        key: &[u8; 32],
        field: &EncryptedField,
        aad: &[u8],
    ) -> Result<Vec<u8>, AppError>;
}

// Атрибут derive с Clone
#[derive(Clone)]
// Структура VaultService
pub struct VaultService<R, C> {
    repo: R,
    crypto: C,
}

// Имплементация VaultService
impl<R, C> VaultService<R, C>
where
    R: VaultRepository,
    C: CryptoPort,
{
    // Ассоциированная функция-конструктор
    pub fn new(repo: R, crypto: C) -> Self {
        Self { repo, crypto }
    }

    // Проверка наличия мастер-пароля в БД
    pub async fn has_master(&self, user_id: i64) -> Result<bool, AppError> {
        Ok(self.repo.get_master(user_id).await?.is_some())
    }

    // Проверка текущего мастер-пароля
    pub async fn verify_current_master(
        &self,
        user_id: i64,
        master_password: &str,
    ) -> Result<(), AppError> {
        let record = self
            .repo
            .get_master(user_id)
            .await?
            .ok_or(AppError::MasterPasswordNotSet)?;
        if master_password.is_empty()
            || !self
                .crypto
                .verify_master_password(master_password, &record)?
        {
            return Err(AppError::InvalidMasterPassword);
        }
        Ok(())
    }

    // Установка мастер-пароля впервые или смена с подтверждением текущего
    // При смене перешифровываются все записи, чтобы совпадал ключ с новым key_salt
    pub async fn set_master(
        &self,
        user_id: i64,
        new_master_password: &str,
        current_master_password: Option<&str>,
    ) -> Result<(), AppError> {
        if new_master_password.is_empty() {
            return Err(AppError::EmptyMasterPassword);
        }

        match self.repo.get_master(user_id).await? {
            None => {
                let record = self.crypto.create_master_record(new_master_password)?;
                self.repo.upsert_master(user_id, record).await
            }
            Some(old_record) => {
                let current = current_master_password.ok_or(AppError::CurrentMasterPasswordRequired)?;
                if current.is_empty()
                    || !self
                        .crypto
                        .verify_master_password(current, &old_record)?
                {
                    return Err(AppError::InvalidMasterPassword);
                }

                let old_key = self.crypto.derive_entry_key(current, &old_record.key_salt)?;
                let new_record = self.crypto.create_master_record(new_master_password)?;
                let new_key = self
                    .crypto
                    .derive_entry_key(new_master_password, &new_record.key_salt)?;

                let services = self.repo.list_services(user_id).await?;
                for service in services {
                    let encrypted = self
                        .repo
                        .get_entry(user_id, &service)
                        .await?
                        .ok_or(AppError::EntryNotFound)?;
                    let aad = format!("{user_id}:{}", encrypted.service);
                    let login_pt = self.crypto.decrypt(&old_key, &encrypted.login, aad.as_bytes())?;
                    let password_pt =
                        self.crypto.decrypt(&old_key, &encrypted.password, aad.as_bytes())?;
                    let note_pt = encrypted
                        .note
                        .as_ref()
                        .map(|f| self.crypto.decrypt(&old_key, f, aad.as_bytes()))
                        .transpose()?;

                    let rotated = EncryptedEntry {
                        service: encrypted.service,
                        login: self.crypto.encrypt(&new_key, &login_pt, aad.as_bytes())?,
                        password: self.crypto.encrypt(&new_key, &password_pt, aad.as_bytes())?,
                        note: note_pt
                            .as_ref()
                            .map(|pt| self.crypto.encrypt(&new_key, pt, aad.as_bytes()))
                            .transpose()?,
                    };
                    self.repo.upsert_entry(user_id, rotated).await?;
                }

                self.repo.upsert_master(user_id, new_record).await
            }
        }
    }

    // Добавление записи
    pub async fn add_entry(
        &self,
        user_id: i64,
        input: PlainEntryInput,
        master_password: &str,
    ) -> Result<(), AppError> {
        // Валидация DTO
        let input = input.validate()?;
        // Чтение криптопараметров мастер-пароля
        let record = self
            .repo
            .get_master(user_id)
            .await?
            .ok_or(AppError::MasterPasswordNotSet)?;
        // Верификация мастер-пароля
        if !self
            .crypto
            .verify_master_password(master_password, &record)?
        {
            return Err(AppError::InvalidMasterPassword);
        }

        // Вывести ключ записи из мастер-пароля и key_salt
        let key = self
            .crypto
            .derive_entry_key(master_password, &record.key_salt)?;
        // Формирование AAD
        let aad = format!("{user_id}:{}", input.service);
        // Сборка EncryptedEntry
        let entry = EncryptedEntry {
            // service - без зашифровки
            service: input.service,
            // Зашифровка login
            login: self
                .crypto
                .encrypt(&key, input.login.as_bytes(), aad.as_bytes())?,
            // Зашифровка password
            password: self
                .crypto
                .encrypt(&key, input.password.as_bytes(), aad.as_bytes())?,
            // Зашифровка note
            note: input
                .note
                .as_ref()
                .map(|note| self.crypto.encrypt(&key, note.as_bytes(), aad.as_bytes()))
                .transpose()?,
        };

        // Сохранить зашифрованную запись в БД
        self.repo.upsert_entry(user_id, entry).await
    }

    // Получение записи
    pub async fn get_entry(
        &self,
        user_id: i64,
        service: &str,
        master_password: &str,
    ) -> Result<PlainEntryView, AppError> {
        // Чтение криптопараметров мастер-пароля
        let record = self
            .repo
            .get_master(user_id)
            .await?
            .ok_or(AppError::MasterPasswordNotSet)?;
        // Проверка мастер-пароля
        if !self
            .crypto
            .verify_master_password(master_password, &record)?
        {
            return Err(AppError::InvalidMasterPassword);
        }
        // Взять зашифрованную запись из БД
        let encrypted = self
            .repo
            .get_entry(user_id, service)
            .await?
            .ok_or(AppError::EntryNotFound)?;
        // Вывести симметричный ключ из мастера и соли
        let key = self
            .crypto
            .derive_entry_key(master_password, &record.key_salt)?;
        // Получение AAD
        let aad = format!("{user_id}:{}", encrypted.service);

        // Расшифровка login
        let login = String::from_utf8(self.crypto.decrypt(
            &key,
            &encrypted.login,
            aad.as_bytes(),
        )?)
        .map_err(|_| AppError::Crypto)?;
        // Расшифровка password
        let password = String::from_utf8(self.crypto.decrypt(
            &key,
            &encrypted.password,
            aad.as_bytes(),
        )?)
        .map_err(|_| AppError::Crypto)?;
        // Расшифровка note
        let note = encrypted
            .note
            .as_ref()
            .map(|field| self.crypto.decrypt(&key, field, aad.as_bytes()))
            .transpose()?
            .map(|bytes| String::from_utf8(bytes).map_err(|_| AppError::Crypto))
            .transpose()?;

        // Успешный Result с PlainEntryView
        Ok(PlainEntryView {
            service: encrypted.service,
            login,
            password,
            note,
        })
    }

    // Получение списка сервисов
    pub async fn list_services(&self, user_id: i64) -> Result<Vec<String>, AppError> {
        self.repo.list_services(user_id).await
    }

    // Удаление записи
    pub async fn delete_entry(&self, user_id: i64, service: &str) -> Result<bool, AppError> {
        self.repo.delete_entry(user_id, service).await
    }
}